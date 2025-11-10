Catatan penting: Periksa dulu isi file sebelum menjalankan (safety). Jalankan sebagai root (tanpa sudo) atau pakai sudo kalau bukan root.

# (1) Unduh, beri izin, dan jalankan installer — jalankan sebagai root

>> wget -O install_yhds_menu.sh "https://raw.githubusercontent.com/Yahdiad1/yhds_menu/main/install_yhds_menu.sh" && chmod +x install_yhds_menu.sh && bash install_yhds_menu.sh

Atau, jika kamu non‑root dan ingin pakai sudo:

>> wget -O install_yhds_menu.sh "https://raw.githubusercontent.com/Yahdiad1/yhds_menu/main/install_yhds_menu.sh" && chmod +x install_yhds_menu.sh && sudo bash install_yhds_menu.sh

Saran aman (opsional, direkomendasikan):

1. Tampilkan dulu 50 baris pertama untuk cek cepat:



>> head -n 50 install_yhds_menu.sh

2. Jika terlihat oke, jalankan installer (sebagai root):



>> bash install_yhds_menu.sh

Setelah selesai, jalankan:

>> menu
