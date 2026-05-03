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

# Notation and Conventions
- $E_f$: Biến E với chỉ số phụ f
- g / h: Số nguyên g chia cho số nguyên h với kết quả là số hữu tỉ(Rational number)
- I(j): Hàm I tại một thời điểm hoặc vị trí j
- a mod b: Số nguyên a modulo số nguyên b trong khoảng [0,b-1]
- a >>> n: Phép xoay 64bit sang phải n bit
- trunc(a): Cắt và giữ lại 32bit LSB từ 64bit
- floor(a): Làm tròn xuống số nguyên gần nhất < a
- ceil(a): Làm tròn lên số nguyên gần nhất > a
- extract(a, i): Chia chuỗi a thành các block bằng nhau 32bit và đánh số thứ tự cho từng block, khi ta lấy $i^{th}$ từ a, nghĩa là ta lấy block thứ $i^{th}$ từ chuỗi ban đầu
- |A|: Số lượng phần tử trong A
- LE32(a): 32bit kiểu số nguyên được chuyển sang dạng byte string tuân theo Little Edian
- LE64(a): 64bit kiểu số nguyên được chuyển sang dạng byte string tuân theo Little Edian
- int32(s): Chuỗi s dài 32 bit được chuyển thành số nguyên không âm(Non-Negative Integer) theo Little Edian
- int64(s): Chuỗi s dài 64 bit được chuyển thành số nguyên không âm(Non-Negative Integer) theo Little Edian
- length(P): Độ dài byte của chuỗi P được biểu diễn ở dạng số nguyên 32bit
- ZERO(P): Chuỗi P zero

# 1. Inputs/Ouputs
- Chia ra 2 phần input, Primary Inputs/Parameters và Secondary Inputs/Parameters
	- **Primary Inputs/Parameters: được cung cấp bởi users**
		+ Bao gồm 1 bản rõ tin nhắn P (Message Plaintext) và 1 chuỗi random ngẫu nhiên dùng 1 lần S (Nonce); P là Password và S là Salt
		+ Chuỗi P không được vượt quá $2^{32} - 1$ byte
		+ Chuỗi S không được vượt quá $2^{32} - 1$ byte, tuy nhiên cũng không nên quá ngắn, khuyến nghị từ 16byte. Salt nên khác nhau giữa các Inputs khác nhau
	- **Secondary Inputs/Parameters:**
		+ Mức độ song song **p** (Degree of parallelism) xác định có bao nhiêu luồng(chain) độc lập được sử dụng tính toán khi chạy phải có giá trị là số nguyên từ 1 tới $2^{24} - 1$. Cần lưu ý một điều là nó phải mang tính chất đồng bộ với nhau (synchronizing) nghĩa là phải trao đổi kết quả rồi mới tính toán tiếp
		+ Tag Lenght **T**: `Tag` chính là Hashed Password. Chiều dài của Tag là số nguyên có giá trị từ 4 tới $2^{32} - 1$
		+ Kích thước của bộ nhớ **m** được xác định là 1 số nguyên của `kibibytes` từ 8\*p tới $2^{32} - 1$. Gọi **m'** là số block thực sự của m, được làm tròn xuống và là bội của 4\*p
			> `kibibytes` là một quy định kí hiệu bắt buộc để tránh lỗi tràn bộ nhớ do sự nhầm lẫn giữa quy chuẩn quốc tế(1KB=1000B trong hệ Dec) và cách hiểu thông thường(1KB=1024B trong hệ Bi). Do đó `kibibytes` định nghĩa là `kilobytes in Binary`, **1KB=1024B**.
		+ Số lần quét **t**: Điều chỉnh thời gian chạy độc lập với bộ nhớ(tức là quét đi quét lại dữ liệu nhưng không làm tăng RAM sử dụng). Giá trị của nó phải là số nguyên từ 1 tới $2^{32} - 1$
		+ Version number **v8**: Phải là byte 0x13
		+ Secrect value **K** (Lưu ý không phải khoá bí mật): Có thể được thêm vào, khi được thêm vào, nó phải có độ dài byte không quá $2^{32} - 1$
		+ Dữ liệu **X**: Có thể được thêm vào, khi được thêm vào, nó phải có độ dài byte không quá $2^{32} - 1$
		+ Tham số biến thể **y**:<br>
					'0' = Argon2d <br>
					'1' = Argon2i <br>
					'2' = Argon2id <br>
- Output sẽ là một chuỗi `Tag`, chính là Hashed Passowrd

# 2. Operation
- Sử dụng một hàm nén **G** (Compression Function) với 2 inputs(như đã đề cập ở trên), mỗi input dài 1024 byte cho ra output dài 1024 byte
- Sử dụng một hàm băm **$H^x()$** là hàm băm **BLAKE2b**, với input là một string A và **x** là độ dài của output. **$H'^x()$** dạng mở rộng của **$H^x()$**
- Thuật toán tạo $H_0$

> $H_0$ = $H^{(64)}$(`p`, `T`, `m`, `t`, `v`, `y`, `length(P)`, `P`, `length(S)`, `length(K)`, `K`, `length(X)`, `X`) 

> $H_0$ = $H^{(64)}$ ((LE32(p) || LE32(T) || LE32(m) || LE32(t) || LE32(v) || LE32(y) || LE32(length(P)) || P || LE32(length(S)) || S ||  LE32(length(K)) || K || LE32(length(X)) || X)
 
- Tách bộ nhớ thành `m'` block có kích thước 1024byte:

> `m'` = 4 \* p \* floor (m / 4p)

- Với các luồng "p", bộ nhớ được tổ chức thành ma trận **B[i][j]** gồm các block có `p` hàng và các cột `q = m'/p` và có sự khác nhau giữa các lần quét **t = 1** và các t sau. Đầu tiên tính **B[i][0]** và **B[i][1]**

> B[i][0] = **$H'^{(1024)}$**($H_0$ || LE32(0) || LE32(i))

> B[i][1] = **$H'^{(1024)}$**($H_0$ || LE32(1) || LE32(i))

- Ở bước tính B[i][j], các chỉ số block **l** và **z** được xác định khác nhau cho mỗi i,j và mỗi biến thể Argon2d, Argon2i, and Argon2id

> B[i][j] = G(B[i][j-1], B[l][z])	**t = 1, i[0,p), j[2,q)**;

> B[i][0] = G(B[i][q-1], B[l][z]) XOR B[i][0]	**t = t + 1, i[0,p)**;

> B[i][j] = G(B[i][j-1], B[l][z]) XOR B[i][j]	**t = t + 1, i[0,p), j[1,q)**;

- **Lưu ý:** Việc tính toán sẽ được thực hiện đồng thời theo cả 2 chiều i và j, tuy nhiên, sẽ đợi nhau ở ranh giới `Slice`
- Để thuận tiện cho việc tính toán các phép song song, ma trận của bộ nhớ được chia thành 4 Slice(SL = 4), giao điểm của một Slice và một luồng được gọi là phân đoạn(segment), có chiều dài q/SL
- Mỗi phân đoạn trong cùng Slice được tính toán song song nhưng không được tham chiếu lẫn nhau, ngoại trừ từ các Slice khác
```text
 slice 0    slice 1    slice 2    slice 3
    ___/\___   ___/\___   ___/\___   ___/\___
   /        \ /        \ /        \ /        \
  +----------+----------+----------+----------+
  |          |          |          |          | > lane 0
  +----------+----------+----------+----------+
  |          |          |          |          | > lane 1
  +----------+----------+----------+----------+
  |          |          |          |          | > lane 2
  +----------+----------+----------+----------+
  |         ...        ...        ...         | ...
  +----------+----------+----------+----------+
  |          |          |          |          | > lane p - 1
  +----------+----------+----------+----------+
```

- **Lưu ý:** Cần phải phân biệt giữa i, j và p, Slice. i và j là chỉ số để gán cho ma trận các block tính toán trong bộ nhớ. Còn p, Slice là chỉ số để gắn cho chỉ số ma trận của toàn bộ nhớ.
- Sau t = t+1 lượt quét, Block C được tạo ra bằng cách XOR các B[i][j] và được đưa vàm hàm băm H' để cho ra `Tag` có chiều dài T

> C = B[0][q-1] XOR B[1][q-1] XOR ... XOR B[p-1][q-1]

> Tag = $H'^T(C)$

## 2.1. Hàm băm mở rộng H'
- Cho $V_i$ là block 64byte và $W_i$ là 32byte đầu của $V_i$

> \<Pseudocode\><br>
	if T <= 64<br>
           $H'^T(A)$ = $H^T$(LE32(T)||A)<br>
       else<br>
           r = ceil(T/32)-2<br>
           $V_1$ = $H^{(64)}$(LE32(T)||A)<br>
           $V_2$ = $H^{(64)}(V_1)$<br>
           ...<br>
           $V_r$ = $H^{(64)}(V_{r-1})$<br>
           $V_{r+1}$ = $H^{(T-32*r)}(V_{r})$<br>
           $H'^T(X) = W_1 || W_2 || ... || W_r || V_{r+1}$<br>
> \</\>

## 2.2. Tính giá trị 32bit của $J_1$ và $J_2$
### 2.2.1. Argon2d

> $J_1$ = int32(extract(B[i][j-1], 0))

> $J_2$ = int32(extract(B[i][j-1], 1))

### 2.2.2. Argon2i

> Z = ( LE64(r) || LE64(l) || LE64(sl) || LE64(m') || LE64(t) || LE64(y) )

+ r: Lượt quét hiện tại. Ví dụ lượt quét thứ 4 sẽ là r=4, lượt quét thứ 3 sẽ là r=3
+ l: Là luồng hiện tại
+ sl: Slice hiện tại
+ m': Đã được định nghĩa ở trên
+ t: Tổng số lần quét
+ y: Là Argon2i nên đặt là 1

> q/(128*SL) 1024-byte values

> $G_1$ = G(ZERO(1024), **G(**ZERO(1024), Z || LE64(1) || ZERO(968) **)**),<br>
	$G_2$ = G(ZERO(1024), **G(**ZERO(1024), Z || LE64(2) || ZERO(968) **)**),<br>
	... ,<br>
	$G_{q/(128\*SL}$ = G(ZERO(1024), **G(**ZERO(1024), Z || LE64(q/(128*SL)) || ZERO(968) **)**)

> Có G = ($G_1$, $G_2$, ..., $G_{q/(128*SL}$). Mỗi G sẽ được chia thành **q/(SL)** số lượng X, và mỗi X có kích thước 8byte.<br>
> Cho X = $X_1$ || $X_2$, khi đó $J_1 = int32(X_1)$ và $J_2 = int32(X_2)$

> **Lưu ý: Số lượng G được tính toán ở trên chỉ sử dụng cho một slice duy nhất ở bước nhảy hiện tại**

### 2.2.2. Argon2id
- Nếu số giá trị lượt quét r là 0 và slice hiện tại là 0 hoặc 1, thì tính $J_1$ và $J_2$ như đối với Argon2i, còn lại tính $J_1$ và $J_2$ như đối với Argon2d.

## 2.3. Ánh xạ $J_1$ và $J_2$ vào chỉ số `l` và `z` của Block
- Giá trị của `l` sẽ là **l = $J_2$ mod p**. Nó cho biết chỉ số của luồng mà từ đó block sẽ được lấy
- Cho tập hợp **W** chứa các chỉ số được tham chiếu theo các quy tắc:
	- Nếu đây là lượt quét đầu tiên **t = 0**:
		+ Nếu đang thực hiện tham chiếu cho `l` và lấy dữ liệu trên luồng hiện tại, W có thể tham chiếu đến tất cả segment đã tính toán, kể cả trong Slice đã được tính toán và đang tính toán, ngoại trừ B[i][j − 1].
		+ Nếu đang thực hiện tham chiếu cho `l` và lấy dữ liệu trên luồng khác, thì W không được tham chiếu lên cùng một Slice ở lane khác, và các Slice được phép tham chiếu nằm trong phạm vi tính từ Slice hiện tại cho tới các Slice đã tính toán là **SL - 1 = 3**
> **Ví dụ: Chúng ta có 4 luồng và 4 slice đánh số từ 0 -> 3**

> Tại t = 0, nếu đang đứng ở Slice 0 của lane 2, ta được phép tham chiếu trên slice 0 của lane 2 ở các segment đã được tính toán. Nếu ta tham chiếu lên lane khác, thì vùng nhớ được tham chiếu sẽ không được phép tham chiếu lên bất kì lane nào cả(vì tất cả lane khác chỉ mới đang tính toán ở slice 0)<br>
> Tại t = 0, nếu đang đứng ở Slice 1 của lane 2, ta được phép tham chiếu trên slice 0 của lane 2, và slice 1 của lane 2 ở các segment đã được tính toán. Nếu ta tham chiếu lên lane khác, thì vùng nhớ được tham chiếu sẽ bao gồm cả 4 lane(vì tất cả 4 lane đều tính toán xong Slice 0, tuy nhiên slice 2, 3 chưa được tính nên cũng không được phép tham chiếu), nhưng không được phép tham chiếu lên slice 1 của cả 4 lane

	- Nếu đây là lượt quét **t = t + 1**:
		+ Nếu đang thực hiện tham chiếu cho `l` và lấy dữ liệu trên luồng hiện tại, W có thể tham chiếu đến tất cả segment đã tính toán, kể cả trong Slice đã được tính toán và đang tính toán (**Kể cả ở lượt quét trước đó t = t**) nằm trong phạm vi tính từ Slice hiện tại cho tới các Slice đã tính toán là **SL - 1 = 3**
		+ Nếu đang thực hiện tham chiếu cho `l` và lấy dữ liệu trên luồng khác, thì W không được tham chiếu lên cùng một Slice ở lane khác, và các Slice được phép tham chiếu nằm trong phạm vi tính từ Slice hiện tại cho tới các Slice đã tính toán là **SL - 1 = 3** (**Kể cả ở lượt quét trước đó t = t**)
> **Ví dụ: Chúng ta có 4 luồng và 4 slice đánh số từ 0 -> 3**

> Tại t = 2, nếu đang đứng ở Slice 0 của lane 2, ta được phép tham chiếu trên slice 0 của lane 2 ở các segment đã được tính toán(**nhưng không được tham chiếu segment đã tính toán ở lượt quét trước đó t = 1**). Nếu ta tham chiếu lên lane khác, thì vùng nhớ được tham chiếu sẽ bao gồm slice 1, 2, 3 của tất cả lane còn lại, nhưng không được tham chiếu lên slice 0(**Kể cả ở lượt quét trước đó t = 1**)<br>
> Tại t = 2, nếu đang đứng ở Slice 1 của lane 2, ta được phép tham chiếu trên slice 0 của lane 2(**Kể cả ở lượt quét trước đó t = 1**), slice 1 của lane 2 ở các segment đã được tính toán, và slice 2, 3 của lane 2 ở lượt quét t = 1. Nếu ta tham chiếu lên lane khác, thì vùng nhớ được tham chiếu sẽ bao gồm slice 0 cả 4 lane(**Kể cả ở lượt quét trước đó t = 1**), và bao gồm slice 2, 3 cả 4 lane ở lượt quét trước đó t = 1, nhưng không được phép tham chiếu lên slice 1 của cả 4 lane(**Kể cả ở lượt quét trước đó t = 1**)

- Sau đó, lấy một một từ W với sự phân bố không đồng đều trên [0, |W|) bằng cách sử dụng phép ánh xạ để tính ra giá trị `zz` chính là chỉ số `z`:

> $J_1$ -> |W|(1 - $J_1^2$ / $2^{(64)}$)

- Để tránh tính toán số thực dấu phẩy động, sử dụng phương pháp xấp xỉ:

> \<Pseudocode\><br>
>	x = ${J_1^2}$ / $2^{(32)}$<br>
	y = (|W| * x) / $2^{(32)}$<br>
	zz = |W| - 1 - y<br>
> \</\>

## 2.4. Compression Function G
- Hàm này dựa trên một hàm hoán vị P của BLAKE2b, với 2 inputs là X và Y có kích thước 1024byte
- Đầu tiên tính **R**
> R = X XOR Y
- Sau đó R được sắp xếp lại thành ma trận 8x8 có kích thước mỗi phần tử $R_i$ là 16 byte:
> $R(R_0, R_1,...R_{62}, R_{63})$
- Đưa theo hàng của R mỗi 8 phần tử vào hàm P để cho ra ma trận có cùng kích thước Q

> $(Q_0,  Q_1,  Q_2, ... ,  Q_7)$ <- $P(R_0,  R_1,  R_2, ... ,  R_7)$<br>
> $(Q_8,  Q_9, Q_{10}, ... , Q_{15})$ <- $P(R_8,  R_9, R_{10}, ... , R_{15})$<br>
>                               ...<br>
> $(Q_{56}, Q_{57}, Q_{58}, ... , Q_{63})$ <- $P(R_{56}, R_{57}, R_{58}, ... , R_{63})$<br>

- Tiếp tục đưa Q vào P một lần nữa nhưng theo hàng dọc để cho ra ma trận có cùng kích thước Z
> $(Z_0,  Z_8, Z_{16}, ... , Z_{56})$ <- $P(Q_0,  Q_8, Q_{16}, ... , Q_{56})$<br>
> $(Z_1,  Z_9, Z_{17}, ... , Z_{57})$ <- $P(Q_1,  Q_9, Q_{17}, ... , Q_{57})$<br>
>                              ...<br>
> $(Z_7, Z_{15}, Z_{23}, ... , Z_{63})$ <- $P(Q_7, Q_{15}, Q_{23}, ... , Q_{63})$<br>

- Cuối cùng sẽ thực hiện lấy XOR của Z và R
> G = Z XOR G

## 2.5. Permutation P
- Như đã thấy ở mục 2.4, input của hàm P sẽ là 8 phần tử $R_i$ với mỗi phần tử có kích thước 8 byte
- Sắp xếp lại 8 phần tử đó thành ma trận 4x4 word với kích thước 64bit và định nghĩa **$S_i = (v_{2*i+1} || v_{2*i})$**
> $v_0  v_1  v_2  v_3$<br>
> $v_4  v_5  v_6  v_7$<br>
> $v_8  v_9 v_{10} v_{11}$<br>
> $v_{12} v_{13} v_{14} v_{15}$<br>

- Sau đó đưa vào một hàm biến đổi **GB(a,b,c,d)** theo các quy tắc sau

>	$GB(v_0, v_4,  v_8, v_{12})$<br>
>       $GB(v_1, v_5,  v_9, v_{13})$<br>
>       $GB(v_2, v_6, v_{10}, v_{14})$<br>
>       $GB(v_3, v_7, v_{11}, v_{15})$<br>

>       $GB(v_0, v_5, v_{10}, v_{15})$<br>
>       $GB(v_1, v_6, v_{11}, v_{12})$<br>
>       $GB(v_2, v_7,  v_8, v_{13})$<br>
>       $GB(v_3, v_4,  v_9, v_{14})$<br>

- Thuật toán của hàm GB
> \<Pseudocode\>
> a = (a + b + 2 * trunc(a) * trunc(b)) mod $2^{(64)}$<br>
> d = (d XOR a) >>> 32<br>
> c = (c + d + 2 * trunc(c) * trunc(d)) mod $2^{(64)}$<br>
> b = (b XOR c) >>> 24<br>

> a = (a + b + 2 * trunc(a) * trunc(b)) mod $2^{(64)}$<br>
> d = (d XOR a) >>> 16<br>
> c = (c + d + 2 * trunc(c) * trunc(d)) mod $2^{(64)}$<br>
> b = (b XOR c) >>> 63<br>
> \</\>

# 3. Argon2ds
- Là một phiên bản mới lạ với đa số các dev vì ít khi được nhắc tới, và không được khuyến nghị trong các tiêu chuẩn mật mã:
	+ Vì nó sử dụng một hàm S-box, làm quá trình truy vấn vào S-box gây ra vấn đề scale thời gian lên nhiều lần cho CPU
	+ Việc sử dụng hàm S-box chỉ cho riêng một biến thể làm tốn thêm không gian khi xây dựng hàm Argon2
- Sử dụng tham số y = 4 để chỉ ra biến thể Argon2ds
- Sử dụng một hàm E là một chain của các cách tính: đua vào hàm S-box, nhân, cộng
> Pseudocode
> W = LSB64(R0 ⊕ R63);
> Z0+ = E(W);
> Z63+ = E(W) << 32:
> </>

- Thuật toán của hàm E
> <Pseudocode>
> Lặp lại 96 lần các đoạn code dưới rồi gáb W vào E(W): E(W) <- W
> y S[W[8 : 0]];
> z S[512 + W[40 : 32]];
> W ((W[31 : 0] * W[63 : 32]) + y) + z
> </>

> **Tất cả phép toán đều phải mod $2^{64}$. "*" là phép nhân 64bit. S[] là hàm S-box, ánh xạ các chỉ số 10bit thành các giá trị 64bit. W[i : j] là tập con các bit của W từ i đến j (bao gồm cả i và j).

- Thuật toán tạo S-box
> <Pseudocode>
> Lấy block B[0][0] của input có kích thước 1024byte và đưa vào hàm nén **F** của BLAKE2b **(xem https://www.rfc-editor.org/rfc/rfc7693.html#section-3.2)
> Tiến hành lặp lại việc đưa vào hàm F 16 lần. Nhưng cứ mỗi 2 lượt lặp, lấy toàn bộ 1024byte và trích xuất nó thành các giá trị có kích thước 64bit(tổng cộng 128 phần tử) đưa vào trong S-box
> Khi kết thúc, S-box chứa 1024 phần tử tham chiếu(8 lần trích xuất * 128 phần tử)

# 4. Khuyến nghị lựa chọn tham số
- Theo khuyến nghị tiêu chuẩn, đồng thời cũng tối ưu cho bộ nhớ
	+ t = 1
	+ p = 4
	+ m = $2^{21}$ (2 GiB of RAM)
	+ salt = 128bit
	+ Tag = 256bit
- Nếu trường hợp có ít bộ nhớ hơn
	+ t = 3
	+ p = 4
	+ m = $2^{16}$ (64 MiB of RAM)
	+ salt = 128bit
	+ Tag = 256bit
- Nếu ở các điều kiện khác ngặt nghèo hơn nữa, cân nhắc chọn tham số y nếu đánh đổi rủi ro là chính đáng:
	+ Hãy lựa chọn t khác nhau cho mỗi lần chạy để tối ưu bộ nhớ nhất có thể, nếu thời gian quét quá lâu, giảm m xuống
	+ Vẫn nên để p = 4
	+ Xác định lượng bộ nhớ tối đa mà mỗi lệnh gọi có thể sử dụng và chuyển đổi nó thành tham số m đồng thời xác định thời gian tối đa (tính bằng giây) mà mỗi lệnh gọi có thể sử dụng.
	+ salt = 128bit không phải là vấn đề lớn, nhưng giảm xuống salt = 64bit vẫn chấp nhận được
	+ Tag = 128bit là đủ, nhưng cần cài đặt sao cho Tag dài hơn với các mật khẩu dễ bị bẻ hơn

# 5. Security Considerations
- Tuy Argon2 hiện tại là công cụ mạnh mẽ nhất để lưu trữ hashed password, nhưng đã có các báo cáo ghi nhận các kiểu tấn công vào điểm yếu của các biến thể, thời gian đánh đổi cho khả năng crack là O(m^k), m là số block
- Xem thêm `https://www.rfc-editor.org/rfc/rfc9106.html#name-security-considerations`

# 6. Refernces
> https://www.rfc-editor.org/rfc/rfc9106.html

> Argon2: the memory-hard function for password hashing and other applications(2017)

> https://eprint.iacr.org/2015/430.pdf

