import React from "react";

const choices = {
  queue: ["Bảng", "Xem nhanh"],
  cases: ["Bảng", "Xem nhanh"],
  alert: ["Đối chiếu", "Theo tab"],
  case: ["Đối chiếu", "Theo tab"],
  soar: ["Bảng phiếu", "Chi tiết phiếu"],
  ti: ["Tổng quan", "Tra cứu IOC"],
};
const reasons = {
  login: "Tài khoản, mật khẩu và phản hồi đăng nhập nằm cùng một biểu mẫu.",
  "admin-overview": "Sức khoẻ hệ thống và các job lỗi nằm đầu trang.",
  "admin-users": "Danh sách tài khoản đi cùng các thao tác theo quyền.",
  "admin-llm": "Hạn mức và số lượt sử dụng nằm cùng màn để đối chiếu.",
  "admin-labels": "Bằng chứng và các lựa chọn nhãn nằm trong cùng phiên đánh giá.",
  "admin-lab": "Danh sách lần chạy đi cùng tiến độ gán nhãn.",
  "admin-lab-run": "Mỗi alert giữ bằng chứng và thao tác gán nhãn trong ngữ cảnh lần chạy.",
  "admin-knowledge": "Danh sách bản nháp dẫn đến nguồn và nội dung cần duyệt.",
  "admin-audit": "Bộ lọc nằm trên danh sách sự kiện. Mỗi dòng mở được payload.",
};
export const hasLayouts = (page) => Object.hasOwn(choices, page);
export function layoutReason(page, layout) {
  if (!hasLayouts(page)) return reasons[page];
  const table = layout === "a";
  if (page === "alert" || page === "case") return table
    ? "Trên màn rộng, bằng chứng và phân tích AI nằm cạnh nhau để đối chiếu."
    : "Các tab dành riêng không gian cho bằng chứng, phân tích AI và thao tác xử lý.";
  if (page === "ti") return table
    ? "Chỉ số và biểu đồ nằm trước bảng IOC để theo dõi nguồn dữ liệu."
    : "Bộ lọc và kết quả IOC nằm đầu trang. Mở từng IOC để đọc chi tiết.";
  if (page === "soar") return table
    ? "Bảng đặt mã phiếu, điểm và quyết định theo cột để so sánh nhiều phiếu."
    : "Các trường của một phiếu nằm cùng thẻ. Chọn mã phiếu để mở chi tiết.";
  return table ? "Các cột thẳng hàng để so sánh bản ghi và sắp xếp danh sách."
    : "Danh sách thẻ đặt cạnh khung xem nhanh. Ở màn hẹp, khung mở ngay dưới bản ghi đã chọn.";
}
export function LayoutButtons({ page, layout, setLayout }) {
  return choices[page].map((label, index) => {
    const value = index === 0 ? "a" : "b";
    return <button type="button" key={value} aria-pressed={layout === value}
      onClick={() => setLayout(value)}>{value.toUpperCase()} · {label}</button>;
  });
}
