// src/features/soar/strongWarning.test.ts — the stronger warning of the dialog and its title. They are worded by the ACTION being
// undone and by `host_critical`: only a host that the configuration of the web lists as critical is called "máy quan trọng", and
// the text says it is the configuration that lists it (not the SOAR). An isolation on an ordinary host says what it does and
// hedges nothing. `strong_warning` is `isolate_host` OR `host_critical`; an old server sends no `host_critical`, which reads as false.
// Whole strings, one per (action type x host_critical).
import { strongTitleOf, strongWarningOf } from "./model";
import { review } from "./fixtures";

const ordinary = (over: Parameters<typeof review>[0]) =>
  review({ strong_warning: true, host_critical: false, host: "web-01", ...over });
const critical = (over: Parameters<typeof review>[0]) =>
  review({ strong_warning: true, host_critical: true, host: "AD-server", ...over });

const CFG = "máy được cấu hình là máy quan trọng (ví dụ máy chủ AD)";
const GROUP = "thuộc các máy được cấu hình là máy quan trọng (ví dụ máy chủ AD)";

describe("undo, by the action that is undone and by host_critical", () => {
  it("isolate_host on an ordinary host: what it does, no hedge", () => {
    expect(strongWarningOf(ordinary({ action_type: "isolate_host" }), "undo")).toBe(
      "Gỡ cách ly web-01 sẽ nối lại máy với mạng ngay. Nếu máy vẫn bị xâm nhập, kẻ tấn công có thể tiếp tục hoạt động và lây lan.",
    );
  });

  it("isolate_host on a critical host: the same, and that the configuration lists the host", () => {
    expect(strongWarningOf(critical({ action_type: "isolate_host" }), "undo")).toBe(
      `Gỡ cách ly AD-server sẽ nối lại máy với mạng ngay. AD-server ${GROUP}; nếu máy vẫn bị xâm nhập, kẻ tấn công có thể tiếp tục hoạt động và lây lan.`,
    );
  });

  it("disable_user: the account can sign in again", () => {
    const over = { action_type: "disable_user", user_name: "administrator" } as const;
    expect(strongWarningOf(ordinary(over), "undo")).toBe(
      "Mở khoá tài khoản administrator trên web-01: tài khoản này sẽ đăng nhập lại được ngay. Nếu tài khoản đã bị chiếm quyền, kẻ tấn công có thể dùng lại nó.",
    );
    expect(strongWarningOf(critical(over), "undo")).toBe(
      `Mở khoá tài khoản administrator trên AD-server: tài khoản này sẽ đăng nhập lại được ngay. AD-server ${GROUP}; nếu tài khoản đã bị chiếm quyền, kẻ tấn công có thể dùng lại nó.`,
    );
  });

  it("block_ip: traffic from the address is allowed again, and how the host relates to the address", () => {
    const over = { action_type: "block_ip", action_target: "79.79.78.202" } as const;
    expect(strongWarningOf(ordinary(over), "undo")).toBe(
      "Gỡ chặn 79.79.78.202: lưu lượng từ địa chỉ này được phép đi qua trở lại. Hãy chắc chắn địa chỉ này không còn nguy hiểm.",
    );
    expect(strongWarningOf(critical(over), "undo")).toBe(
      `Gỡ chặn 79.79.78.202: lưu lượng từ địa chỉ này được phép đi qua trở lại. Địa chỉ này đã nhắm tới AD-server, một ${CFG}; hãy chắc chắn địa chỉ này không còn nguy hiểm.`,
    );
  });

  it("sinkhole_domain: the domain resolves again, and how the host relates to it", () => {
    const over = { action_type: "sinkhole_domain", action_target: "evil.example" } as const;
    expect(strongWarningOf(ordinary(over), "undo")).toBe(
      "Gỡ chặn tên miền evil.example: tên miền này sẽ phân giải trở lại. Hãy chắc chắn tên miền này không còn nguy hiểm.",
    );
    expect(strongWarningOf(critical(over), "undo")).toBe(
      `Gỡ chặn tên miền evil.example: tên miền này sẽ phân giải trở lại. Tên miền này đã được truy vấn từ AD-server, một ${CFG}; hãy chắc chắn tên miền này không còn nguy hiểm.`,
    );
  });

  it("disable_xp_cmdshell: xp_cmdshell is enabled again on the host", () => {
    const over = { action_type: "disable_xp_cmdshell" } as const;
    expect(strongWarningOf(ordinary(over), "undo")).toBe(
      "xp_cmdshell sẽ được bật lại trên web-01: máy chủ SQL cho phép chạy lệnh hệ điều hành trở lại. Hãy chắc chắn trước khi tiếp tục.",
    );
    expect(strongWarningOf(critical(over), "undo")).toBe(
      `xp_cmdshell sẽ được bật lại trên AD-server: máy chủ SQL cho phép chạy lệnh hệ điều hành trở lại. AD-server ${GROUP}; hãy chắc chắn trước khi tiếp tục.`,
    );
  });

  it("an action type it does not know: a generic sentence that names the action text", () => {
    const over = { action_type: "make_coffee" as never, action_text: "Pha cà phê" };
    expect(strongWarningOf(ordinary(over), "undo")).toBe(
      "Bạn sắp gỡ biện pháp “Pha cà phê”. Hãy chắc chắn trước khi tiếp tục.",
    );
    expect(strongWarningOf(critical(over), "undo")).toBe(
      `Bạn sắp gỡ biện pháp “Pha cà phê” liên quan tới AD-server, một ${CFG}; hãy chắc chắn trước khi tiếp tục.`,
    );
  });

  it("falls back to plain words when n8n sent no host, account, address or domain, and a critical flag without a host is not claimed", () => {
    const bare = { host: null, user_name: null, action_target: null };
    expect(strongWarningOf(ordinary({ ...bare, action_type: "isolate_host" }), "undo")).toMatch(
      /^Gỡ cách ly máy này sẽ nối lại máy với mạng ngay\./,
    );
    expect(strongWarningOf(ordinary({ ...bare, action_type: "disable_user" }), "undo")).toMatch(
      /^Mở khoá tài khoản này trên máy này: tài khoản này sẽ đăng nhập lại được ngay\./,
    );
    expect(strongWarningOf(ordinary({ ...bare, action_type: "block_ip" }), "undo")).toMatch(
      /^Gỡ chặn địa chỉ này: /,
    );
    expect(strongWarningOf(ordinary({ ...bare, action_type: "sinkhole_domain" }), "undo")).toMatch(
      /^Gỡ chặn tên miền này: /,
    );
    const noHost = strongWarningOf(critical({ ...bare, action_type: "block_ip" }), "undo");
    expect(noHost).not.toContain("quan trọng");
  });

  it("says máy quan trọng only for a critical host, and never says the SOAR marks it", () => {
    for (const action_type of [
      "isolate_host",
      "disable_user",
      "block_ip",
      "sinkhole_domain",
      "disable_xp_cmdshell",
      "kill_process",
    ] as const) {
      const plain = strongWarningOf(ordinary({ action_type }), "undo");
      expect(plain, action_type).not.toContain("quan trọng");
      expect(plain, action_type).not.toContain("máy chủ AD");
      const loud = strongWarningOf(critical({ action_type }), "undo");
      expect(loud, action_type).toContain("được cấu hình là máy quan trọng (ví dụ máy chủ AD)");
      expect(loud, action_type).not.toContain("SOAR");
    }
  });

  it("reads a review that has no host_critical (an older server) as not critical", () => {
    const old = review({ strong_warning: true, host: "AD-server", action_type: "block_ip" });
    delete (old as { host_critical?: boolean }).host_critical;
    expect(strongWarningOf(old, "undo")).not.toContain("quan trọng");
    expect(strongTitleOf(old, "undo")).toBe("Gỡ biện pháp đã áp dụng?");
  });

  it("never describes a non-isolation as an isolation", () => {
    for (const action_type of [
      "block_ip",
      "disable_user",
      "sinkhole_domain",
      "disable_xp_cmdshell",
    ] as const) {
      for (const make of [ordinary, critical]) {
        const text = strongWarningOf(make({ action_type }), "undo");
        expect(text, action_type).not.toContain("Gỡ cách ly");
        expect(text, action_type).not.toContain("nối lại máy với mạng");
      }
    }
  });
});

describe("false positive, by the action of the ticket and by host_critical", () => {
  it("kill_process", () => {
    expect(strongWarningOf(ordinary({ action_type: "kill_process" }), "fp")).toBe(
      "Tiến trình đã bị dừng trên web-01. Nếu đây là tấn công thật, đánh dấu dương tính giả sẽ đóng phiếu và không còn nhắc nữa.",
    );
    expect(strongWarningOf(critical({ action_type: "kill_process" }), "fp")).toBe(
      `Tiến trình đã bị dừng trên AD-server, một ${CFG}. Nếu đây là tấn công thật, đánh dấu dương tính giả sẽ đóng phiếu và không còn nhắc nữa.`,
    );
  });

  it("any other action names it, and on an ordinary isolated host claims no importance", () => {
    const over = { action_type: "isolate_host", action_text: "Cách ly web-01" } as const;
    const plain = strongWarningOf(ordinary(over), "fp");
    expect(plain).toBe(
      "Đánh dấu dương tính giả cho “Cách ly web-01” sẽ đóng phiếu, kể cả khi biện pháp vẫn đang áp dụng. Nếu đây là tấn công thật, sẽ không còn nhắc nữa.",
    );
    expect(plain).not.toContain("quan trọng");
    expect(plain).not.toContain("Tiến trình");
    expect(strongWarningOf(critical(over), "fp")).toBe(
      `Đánh dấu dương tính giả cho “Cách ly web-01” sẽ đóng phiếu, kể cả khi biện pháp vẫn áp dụng trên AD-server, một ${CFG}. Nếu đây là tấn công thật, sẽ không còn nhắc nữa.`,
    );
  });
});

describe("the title of the strong dialog names importance only for a critical host", () => {
  it("undo", () => {
    expect(strongTitleOf(critical({ action_type: "block_ip" }), "undo")).toBe(
      "Cảnh báo: gỡ biện pháp trên máy quan trọng",
    );
    expect(strongTitleOf(critical({ action_type: "isolate_host" }), "undo")).toBe(
      "Cảnh báo: gỡ biện pháp trên máy quan trọng",
    );
    expect(strongTitleOf(ordinary({ action_type: "isolate_host" }), "undo")).toBe(
      "Cảnh báo: gỡ cách ly máy",
    );
  });

  it("fp", () => {
    expect(strongTitleOf(critical({ action_type: "kill_process" }), "fp")).toBe(
      "Cảnh báo: đánh dấu dương tính giả trên máy quan trọng",
    );
    expect(strongTitleOf(ordinary({ action_type: "isolate_host" }), "fp")).toBe(
      "Cảnh báo: đánh dấu dương tính giả cho máy bị cách ly",
    );
  });

  it("is the ordinary title when there is no strong warning, and when the warning has no reason the web can name", () => {
    expect(strongTitleOf(review(), "undo")).toBe("Gỡ biện pháp đã áp dụng?");
    expect(strongTitleOf(review(), "fp")).toBe("Đánh dấu dương tính giả?");
    expect(strongTitleOf(ordinary({ action_type: "block_ip" }), "undo")).toBe(
      "Gỡ biện pháp đã áp dụng?",
    );
  });
});
