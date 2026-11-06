AIMLOCK PEDINHIOS - WEB ADMIN

CẤU TRÚC
- api/server.js
- api/public/index.html

CÀI ĐẶT
1. Thay file api/server.js hiện tại bằng file trong gói.
2. Thay api/public/index.html bằng file trong gói.
3. Giữ nguyên package.json và các dependencies hiện có: express, helmet, express-rate-limit, pg.
4. Trên Render, giữ DATABASE_URL và KEY_HASH_SALT hiện có.
5. Thêm các Environment Variables:
   ADMIN_USERNAME = tài khoản Admin bạn tự đặt
   ADMIN_PASSWORD = mật khẩu Admin mạnh do bạn tự đặt
   SESSION_SECRET = chuỗi bí mật ngẫu nhiên dài tối thiểu 32 ký tự
   NODE_ENV = production
   ADMIN_TOKEN = có thể giữ token cũ (tùy chọn; hỗ trợ client quản trị cũ)
6. Deploy lại Render. Khi khởi động, API tự thêm các cột và bảng còn thiếu.

ĐƯỜNG DẪN
- Trang Admin: /
- Health: /health
- Đăng nhập: POST /api/admin/login
- Kiểm tra phiên: GET /api/admin/session
- Đăng xuất: POST /api/admin/logout
- App verify giữ nguyên: POST /api/keys/verify
- Admin list/create: GET/POST /api/admin/keys
- Khóa/mở: POST /api/admin/keys/:id/lock hoặc /unlock
- Xóa: DELETE /api/admin/keys/:id

LƯU Ý QUAN TRỌNG VỀ GIỚI HẠN THIẾT BỊ
- Các Key tạo mới bật kiểm tra thiết bị ở API.
- Ứng dụng Flutter phải gửi thêm deviceId ổn định cùng key trong POST /api/keys/verify.
  Ví dụ JSON: {"key":"AIM-ABCD-EF01-2345-6789","deviceId":"mã-thiết-bị-ổn-định"}
- Nếu app hiện tại chỉ gửi { "key": "..." }, xác thực Key mới sẽ trả code DEVICE_ID_REQUIRED.
  Cần cập nhật Flutter để tạo/lưu deviceId ổn định trên máy và gửi kèm mỗi lần xác thực.
- Key cũ trong database được giữ tương thích với app cũ (device_limit_enforced=false).
- Server chỉ lưu HMAC của mã thiết bị, không lưu nguyên mã thiết bị.
- Key vĩnh viễn có expires_at = NULL.

AN TOÀN
- Không gửi ADMIN_PASSWORD, SESSION_SECRET, DATABASE_URL hoặc KEY_HASH_SALT vào chat/GitHub.
- Cookie đăng nhập HttpOnly, SameSite=Strict, Secure khi NODE_ENV=production; phiên hết hạn sau 8 giờ.
- Đây là gói mã nguồn; chưa được triển khai lên Render cho đến khi bạn thay file và cấu hình biến môi trường.
