# IDA_Scripts
Các IDC, IDAPython scripts và plugins nhỏ, có ích trong quá trình dùng IDA.
# ida.idc
Backup file ida.idc cũ của bạn trong IDADIR\idc, copy file này vào.
Bổ sung 6 cặp phím tắt:
1. Shift-U: convert to Unicode String tại current screen EA.
2. Alt+Shift+Up: Nhảy tới đầu hàm hiện tại.
3. Alt+Shift+Down: Nhảy tới cuối hàm hiện tại.
4. Ctrl+Alt+Up: Nhảy tới label ở kế trên.
5. Ctrl+Alt+Down: Nhảy tới label ở kế dưới.
6. Shift-P: name a pointer.

4 và 5 rất hửu ích khi chúng ta ở trong 1 vùng undefined code, data thiệt dài, nhảy tới label up và down để dễ define.

6 được dùng để auto name 1 label nếu label đó là 1 pointer.

Vd ta có:

off_xxxyyyzzz dd offset GetProcAddress

Shift-P tại off_xxxyyyzzz ta sẽ có name là p_GetProcAdress.

Tương tự cho các loại khác.  Thử Shift-P thí xác sẽ thấy tác dụng của nó. Thuận tiện hơn cho chúng ta khi đọc mã ASM và mã decompile.

File ida.idc chúng ta không cần phải load và run, mặc định IDA sẽ load và excute hàm main() cho chúng ta.

Nên các hotkeys là có sẵn ngay.

Nếu có tranh chấp với hotkeys khác bạn đang dùng (mình đã chọn và cân nhắc kỹ), các bạn vào Options - Shortcuts... và Show command palettes...

Kiểm tra và edit lại với hotkeys bạn chọn trong file ida.idc này.

# vb_DllFunctionCall.py
Source gốc từ bài: https://blog.talosintelligence.com/discovering-dynamically-loaded-api-in/

Đã thay đổi các struct theo kết quả RE msvbvm60.dll với .dbg file.

Fix vài lỗi và port hẳn qua IDA 7.x, IDAPython3 không BC95
