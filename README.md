# IDA_Scripts
Các IDC và IDAPython scripts nhỏ, có ích trong quá trình dùng IDA
# ida.idc
Backup file ida.idc cũ của bạn trong IDADIR\idc, copy file này vào.
Bổ sung 5 cặp phím tắt:
1. Shift-U: convert to Unicode String tại current screen EA.
2. Alt+Shift+Up: Nhảy tới đầu hàm hiện tại.
3. Alt+Shift+Down: Nhảy tới cuối hàm hiện tại.
4. Ctrl+Alt+Up: Nhảy tới label ở kế trên
5. Ctrl+Alt+Down: Nhảy tới label ở kế dưới.

4 và 5 rất hửu ích khi chúng ta ở trong 1 vùng undefined code, data thiệt dài, nhảy tới label up và down để dễ define.

File ida.idc chúng ta không cần phải load và run, mặc định IDA sẽ load và excute hàm main() cho chúng ta.
Nên các hotkeys là có sẵn ngay.

Nếu có tranh chấp với hotkeys khác bạn đang dùng (mình đã chọn và cân nhắc kỹ), các bạn vào Options - Shortcuts... và Show command palettes...
kiểm tra và edit lại với hotkeys bạn chọn trong file ida.idc này.
