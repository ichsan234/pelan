# Pelan

WebApp pendamping tumbuh kembang dan kemandirian anak usia 0–5 tahun.

## Menjalankan

Node.js 22 atau lebih baru, tanpa dependency eksternal.

    npm run build
    npm test
    node preview.mjs

Preview lokal pada http://localhost:4173 hanya menampilkan UI; akun dan penyimpanan harus diuji dengan binding R2 privat. auth-test.mjs memakai bucket terisolasi untuk pengujian server.

## Infrastruktur

- Server: Cloudflare Workers melalui Sites.
- Penyimpanan: binding R2 BUCKET, tidak memiliki rute unduh publik.
- Situs publik: https://pelan-parenting-demo.maltednote2.chatgpt.site/
- Kode: https://github.com/ichsan234/pelan
- Deployment masih melalui Sites; push GitHub belum memicu deploy otomatis.

## Akun internal

Pendaftaran email/password langsung membuat akun aktif. Password 12–128 karakter di-hash menggunakan PBKDF2-SHA256 (100.000 iterasi, salt acak) kemudian HMAC-SHA256 dengan pepper rahasia server. AUTH_PASSWORD_PEPPER wajib disetel sebagai secret runtime dan tidak boleh diganti tanpa rencana migrasi kredensial.

Cookie sesi __Host-pelan_session memakai Secure, HttpOnly, SameSite=Lax, berlaku 7 hari; hanya hash token yang disimpan. Setiap operasi data memeriksa sesi di server. Login dibatasi berdasarkan IP dan email dengan counter tersimpan dan conditional writes. Pendaftaran email ganda dilindungi conditional create atomik.

Kode pemulihan acak ditampilkan sekali; hash-nya disimpan privat. Pemulihan mengganti password, merotasi kode, dan membatalkan semua sesi lama. Verifikasi kepemilikan email serta pengiriman email belum aktif. Akun tidak ditautkan otomatis berdasarkan alamat email ke akun ChatGPT lama. Login ChatGPT tetap tersedia untuk mengakses data lama.

Pengguna menyetujui pembuatan akun sebelum daftar dan persetujuan data anak pada akhir onboarding. Data per akun berada pada key server tersendiri. Hapus akun memerlukan sesi aktif dan password saat ini.

Media anak, kolaborasi pengasuh, dan pembayaran belum terintegrasi. Tidak ada diagnosis atau program terapi otomatis.

Jangan memasukkan token, password pengguna, secret runtime, atau data keluarga ke GitHub. Jangan menjalankan Worker di luar gateway Sites tanpa memverifikasi ulang sumber header identitas ChatGPT.
