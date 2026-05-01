# Written By Michael Phan
# Structure of Argon2
# Định nghĩa
- Là một thuật toán hàm băm (Hash Function) dạng yêu cầu nhiều bộ nhớ để tính toán (Memory-Hard Function-MHF) với mục tiêu là làm đầy bộ nhớ nhiều nhất 
	- và song song với đó cũng phải đạt hiệu quả tính toán nhiều nhất có thể để chống lại các cuộc tấn công dạng BruteForce và Side Channel Attack
- Được tối ưu hoá cho kiến trúc x86, khai thác cache và bộ nhớ của các bộ xử lý Intel, AMD
- Có một biến thể chính Argon2id là sự kết hợp của 2 biến thể bổ sung Argon2i và Argon2d
	+ Argon2i: sử dụng phương thức truy cập độc lập dữ liệu bộ nhớ(Data-Independent Memory), phù hợp cho tính ứng dụng hash và dẫn xuất khoá dựa trên mật khẩu(Password-Based Key Derivation)
	+ Argon2d: sử dụng phương thức truy cập dựa vào dữ liệu bộ nhớ(Data-Dependent Memory), phù hợp cho tiền điện tử(Cryptocurrencies) và bảo chứng điện tử(Proof of Work) trong Blockchain
- Argon2id thể hiện khả năng của Argon2i ở nửa đầu quá trình duyệt bộ nhớ lần đầu tiên và Argon2d ở các giai đoạn còn lại

#Notation and Conventions
- $E_f$: Biến E với chỉ số phụ f
- g / h: Số nguyên g chia cho số nguyên h với kết quả là số hữu tỉ(Rational number)
- I(j): Hàm I tại một thời điểm hoặc vị trí j
- a mod b: Số nguyên a modulo số nguyên b trong khoảng [0,b-1]
- a >>> n: Phép xoay 64bit sang phải n bit
- trunc(a): Cắt và giữ lại 32bit LSB từ 64bit
- floor(a): Làm tròn xuống số nguyên gần nhất < a
- ceil(a): Làm tròn lên số nguyên gần nhất > a
- extract(a, i): Chia chuỗi a thành các block bằng nhau 32bit và đánh số thứ tự cho từng block, khi ta lấy $i^th$ từ a, nghĩa là ta lấy block thứ $i^th$ từ chuỗi ban đầu
- |A|: Số lượng phần tử trong A
- LE32(a): 32bit kiểu số nguyên được chuyển sang dạng byte string tuân theo Little Edian
- LE64(a): 64bit kiểu số nguyên được chuyển sang dạng byte string tuân theo Little Edian
- int32(s): Chuỗi s dài 32 bit được chuyển thành số nguyên ko âm(Non-Negative Integer) theo Little Edian
- int64(s): Chuỗi s dài 64 bit được chuyển thành số nguyên ko âm(Non-Negative Integer) theo Little Edian
- length(P): Độ dài byte của chuỗi P được biểu diễn ở dạng số nguyên 32bit
- ZERO(P): Chuỗi P zero

# 1. Inputs/Ouputs
- Chia ra 2 phần input, Primary Inputs/Parameters và Secondary Inputs/Parameters
	- Primary Inputs/Parameters: được cung cấp bởi users
		+ Bao gồm 1 bản rõ tin nhắn P (Message Plaintext) và 1 chuỗi random ngẫu nhiên dùng 1 lần S (Nonce); P là Password và S là Salt
		+ Chuỗi P không được vượt quá $2^32 - 1$ byte
		+ Chuỗi S không được vượt quá $2^32 - 1$ byte, tuy nhiên cũng không nên quá ngắn, khuyến nghị từ 16byte. Salt nên khác nhau giữa các Inputs khác nhau
	- Secondary Inputs/Parameters:
		+ Mức độ song song "p" (Degree of parallelism) xác định có bao nhiêu luồng(chain) độc lập được sử dụng tính toán khi chạy phải có giá trị là số nguyên từ 1 tới $2^24 - 1$. Cần lưu ý một điều là nó phải mang tính chất đồng bộ với nhau (synchronizing) nghĩa là phải trao đổi kết quả rồi mới tính toán tiếp
		+ Tag Lenght "T": `Tag` chính là Hashed Password. Chiều dài của Tag là số nguyên có giá trị từ 4 tới $2^32 - 1$
		+ Kích thước của bộ nhớ "m" được xác định là 1 số nguyên của `kibibytes` từ 8*p tới $2^32 - 1$. Gọi m' là số block thực sự của m, được làm tròn xuống và là bội của 4*p
			+ > `kibibytes` là một quy định bắt buộc để tránh lỗi tràn bộ nhớ do sự nhầm lẫn giữa quy chuẩn quốc tế(1KB=1000B trong hệ Dec) và cách hiểu thông thường(1KB=1024B trong hệ Bi). Do đó `kibibytes` định nghĩa là `kilobytes in Binary`, **1KB=1024B**.
		+ Số lần quét "t": Điều chỉnh thời gian chạy độc lập với bộ nhớ(tức là quét đi quét lại dữ liệu nhưng không làm tăng RAM sử dụng). Giá trị của nó phải là số nguyên từ 1 tới $2^32 - 1$
		+ Version number "v": Phải là byte 0x13
		+ Secrect value "K" (Lưu ý không phải khoá bí mật): Có thể được thêm vào, khi được thêm vào, nó phải có độ dài byte không quá $2^32 - 1$
		+ Dữ liệu "X": Có thể được thêm vào, khi được thêm vào, nó phải có độ dài byte không quá $2^32 - 1$
		+ Tham số biến thể "y":<br>
					'0' = Argon2d <br>
					'1' = Argon2i <br>
					'2' = Argon2id <br>
- Output sẽ là một chuỗi `Tag`, chính là Hashed Passowrd

# 2. Operation
- Sử dụng một hàm nén G (Compression Function) với 2 inputs(như đã đề cập ở trên), mỗi input dài 1024 byte cho ra output dài 1024 byte
- Sử dụng một hàm băm $H^x()$, x là độ dài của output
 



