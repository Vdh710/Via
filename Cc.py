import requests
import time

# Đường dẫn API
URL = "https://chinh.grarena.eu.org/ulp.php"

def get_account():
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    }
    
    try:
        response = requests.get(URL, headers=headers, timeout=10)
        
        if response.status_code == 200:
            data_json = response.json()
            
            # Trích xuất giá trị trường 'data' trong đối tượng 'result'
            raw_data = data_json.get("result", {}).get("data", "")
            
            if raw_data and "|" in raw_data:
                # Chuyển đổi định dạng từ tk|mk thành tk:mk
                formatted_data = raw_data.replace("|", ":")
                return formatted_data
            elif raw_data:
                return raw_data
            else:
                print("[-] Không tìm thấy dữ liệu 'data' hợp lệ trong phản hồi.")
        else:
            print(f"[-] Yêu cầu thất bại (HTTP status: {response.status_code})")
            
    except Exception as e:
        print(f"[-] Đã xảy ra lỗi khi kết nối: {e}")
    
    return None

def main():
    print("========================================")
    print("    TOOL LẤY DATA ACCOUNT (tk:mk)       ")
    print("========================================")
    
    try:
        count = int(input("Nhập số lượng tài khoản muốn lấy (mặc định 1): ") or "1")
    except ValueError:
        count = 1

    saved_accounts = []
    
    for i in range(1, count + 1):
        print(f"[{i}/{count}] Đang gửi yêu cầu lấy dữ liệu...")
        acc = get_account()
        
        if acc:
            print(f"  -> Kết quả: {acc}")
            saved_accounts.append(acc)
            
            # Ghi nối (append) vào file accounts.txt
            with open("accounts.txt", "a", encoding="utf-8") as f:
                f.write(acc + "\n")
        else:
            print("  -> Thất bại!")
        
        # Tạm dừng 1 giây giữa các lần gửi request để tránh bị chặn IP
        if i < count:
            time.sleep(1)

    print("\n========================================")
    print(f"[+] Hoàn tất! Đã lấy và lưu {len(saved_accounts)} tài khoản vào file 'accounts.txt'.")

if __name__ == "__main__":
    main()
  
