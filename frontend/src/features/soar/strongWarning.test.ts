// src/features/soar/strongWarning.test.ts — the stronger warning of the dialog is worded by the ACTION being undone, never by
// the Owner's example for every action: `strong_warning` is also true for any action on the domain controller, and the web does
// not know which reason made it true, so no text claims the host is the AD server. Whole strings, one per action type.
import { strongWarningOf } from "./model";
import { review } from "./fixtures";

const strong = (over: Parameters<typeof review>[0]) =>
  review({ strong_warning: true, host: "AD-server", ...over });

describe("undo, by the action that is undone", () => {
  it("isolate_host: reconnecting the host to the network, naming it, claiming nothing about why it matters", () => {
    expect(strongWarningOf(strong({ action_type: "isolate_host" }), "undo")).toBe(
      "Gỡ cách ly AD-server sẽ nối lại máy với mạng ngay. Đây là máy đang bị cách ly hoặc máy mà SOAR đánh dấu quan trọng (ví dụ máy chủ AD). Nếu máy vẫn bị xâm nhập, kẻ tấn công có thể tiếp tục hoạt động và lây lan.",
    );
  });

  it("disable_user: the account can sign in again", () => {
    expect(
      strongWarningOf(strong({ action_type: "disable_user", user_name: "administrator" }), "undo"),
    ).toBe(
      "Mở khoá tài khoản administrator trên AD-server: tài khoản này sẽ đăng nhập lại được ngay. AD-server là máy mà SOAR đánh dấu quan trọng; nếu tài khoản đã bị chiếm quyền, kẻ tấn công có thể dùng lại nó.",
    );
  });

  it("block_ip: traffic from the address is allowed again", () => {
    expect(
      strongWarningOf(strong({ action_type: "block_ip", action_target: "79.79.78.202" }), "undo"),
    ).toBe(
      "Gỡ chặn 79.79.78.202: lưu lượng từ địa chỉ này được phép đi qua trở lại. AD-server là máy mà SOAR đánh dấu quan trọng; hãy chắc chắn địa chỉ này không còn nguy hiểm.",
    );
  });

  it("sinkhole_domain: the domain resolves again", () => {
    expect(
      strongWarningOf(
        strong({ action_type: "sinkhole_domain", action_target: "evil.example" }),
        "undo",
      ),
    ).toBe(
      "Gỡ chặn tên miền evil.example: tên miền này sẽ phân giải trở lại. AD-server là máy mà SOAR đánh dấu quan trọng; hãy chắc chắn tên miền này không còn nguy hiểm.",
    );
  });

  it("disable_xp_cmdshell: xp_cmdshell is enabled again on the host", () => {
    expect(strongWarningOf(strong({ action_type: "disable_xp_cmdshell" }), "undo")).toBe(
      "xp_cmdshell sẽ được bật lại trên AD-server: máy chủ SQL cho phép chạy lệnh hệ điều hành trở lại. AD-server là máy mà SOAR đánh dấu quan trọng; hãy chắc chắn trước khi tiếp tục.",
    );
  });

  it("an action type it does not know: a generic sentence that names the action's own text", () => {
    expect(
      strongWarningOf(
        strong({ action_type: "make_coffee" as never, action_text: "Pha cà phê cho AD" }),
        "undo",
      ),
    ).toBe(
      "Bạn sắp gỡ biện pháp “Pha cà phê cho AD”. AD-server là máy mà SOAR đánh dấu quan trọng; hãy chắc chắn trước khi tiếp tục.",
    );
  });

  it("falls back to plain words when n8n sent no host, account, address or domain", () => {
    const bare = { host: null, user_name: null, action_target: null };
    expect(strongWarningOf(strong({ ...bare, action_type: "isolate_host" }), "undo")).toMatch(
      /^Gỡ cách ly máy này sẽ nối lại máy với mạng ngay\./,
    );
    expect(strongWarningOf(strong({ ...bare, action_type: "disable_user" }), "undo")).toMatch(
      /^Mở khoá tài khoản này trên máy này: tài khoản này sẽ đăng nhập lại được ngay\./,
    );
    expect(strongWarningOf(strong({ ...bare, action_type: "block_ip" }), "undo")).toMatch(
      /^Gỡ chặn địa chỉ này: /,
    );
    expect(strongWarningOf(strong({ ...bare, action_type: "sinkhole_domain" }), "undo")).toMatch(
      /^Gỡ chặn tên miền này: /,
    );
  });

  it("never says the host is the AD server except as an example, for any action type", () => {
    for (const action_type of [
      "isolate_host",
      "disable_user",
      "block_ip",
      "sinkhole_domain",
      "disable_xp_cmdshell",
      "kill_process",
    ] as const) {
      const text = strongWarningOf(strong({ action_type, host: "db-01" }), "undo");
      expect(text, action_type).not.toMatch(/db-01 là máy chủ AD|máy chủ AD db-01/);
    }
    expect(strongWarningOf(strong({ action_type: "block_ip" }), "undo")).not.toContain(
      "Gỡ cách ly",
    );
    expect(strongWarningOf(strong({ action_type: "disable_user" }), "undo")).not.toContain(
      "nối lại máy với mạng",
    );
  });
});

describe("false positive, by the action of the ticket", () => {
  it("kill_process: the process that was stopped", () => {
    expect(strongWarningOf(strong({ action_type: "kill_process" }), "fp")).toBe(
      "Tiến trình đã bị dừng trên AD-server, một máy mà SOAR đánh dấu quan trọng. Nếu đây là tấn công thật, đánh dấu dương tính giả sẽ đóng phiếu và không còn nhắc nữa.",
    );
  });

  it("any other action: a generic sentence that names the action, and does not talk of a stopped process", () => {
    const text = strongWarningOf(
      strong({ action_type: "block_ip", action_text: "Chặn IP 79.79.78.202 trên pfSense" }),
      "fp",
    );
    expect(text).toBe(
      "Đánh dấu dương tính giả cho “Chặn IP 79.79.78.202 trên pfSense” sẽ đóng phiếu, kể cả khi biện pháp vẫn áp dụng trên AD-server, một máy mà SOAR đánh dấu quan trọng. Nếu đây là tấn công thật, sẽ không còn nhắc nữa.",
    );
    expect(text).not.toContain("Tiến trình");
  });
});
