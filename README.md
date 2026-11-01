# Pelan

WebApp pendamping tumbuh kembang dan kemandirian anak usia 0–5 tahun.

## Menjalankan pemeriksaan

Gunakan Node.js 22 atau lebih baru.

    npm run build
    npm test
    node preview.mjs

Preview lokal: http://localhost:4173. Preview lokal tidak menyediakan identitas login atau penyimpanan cloud.

## Infrastruktur saat ini

- Server: Cloudflare Workers melalui Sites.
- Data keluarga: R2 privat, binding BUCKET.
- Identitas: header akun yang diverifikasi oleh Sites.
- Deploy aktif: https://pelan-parenting-demo.maltednote2.chatgpt.site/

Kode sumber tersimpan di repository privat https://github.com/ichsan234/pelan. Deployment cloud saat ini masih dikelola melalui Sites; push ke GitHub belum memicu deployment otomatis. Jangan mengarahkan Worker ini langsung ke internet di luar Sites tanpa mengganti verifikasi identitas: header identitas harus berasal dari gateway tepercaya.

Login email/password, email pemulihan, pembayaran, unggah media, dan kolaborasi pengasuh belum terintegrasi.

Jangan memasukkan password, token, atau data keluarga ke repository.
