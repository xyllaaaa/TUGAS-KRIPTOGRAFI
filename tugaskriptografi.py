import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext, filedialog
from datetime import datetime
from collections import defaultdict, Counter

# =====================================================================
# MODUL LOGIKA KRIPTOGRAFI (VIGENERE, VARIAN, HILL, & KASISKI)
# =====================================================================

class KriptografiEngine:
    @staticmethod
    def bersihkan(teks, hapus_spasi=True):
        teks = teks.upper()
        if hapus_spasi:
            return ''.join(c for c in teks if 'A' <= c <= 'Z')
        return ''.join(c for c in teks if ('A' <= c <= 'Z') or c == ' ')

    @classmethod
    def vigenere_standar(cls, teks, kunci, mode='enkripsi', hapus_spasi=True):
        teks_olah = cls.bersihkan(teks, hapus_spasi)
        kunci_olah = cls.bersihkan(kunci, hapus_spasi=True)
        if not kunci_olah:
            raise ValueError("Kunci tidak boleh kosong!")

        hasil, langkah = [], []
        idx_k = 0
        for ch in teks_olah:
            if ch == ' ':
                hasil.append(' ')
                continue
            p = ord(ch) - 65
            k_char = kunci_olah[idx_k % len(kunci_olah)]
            k = ord(k_char) - 65
            c = (p + k) % 26 if mode == 'enkripsi' else (p - k) % 26
            c_char = chr(c + 65)
            hasil.append(c_char)
            op = "+" if mode == 'enkripsi' else "-"
            langkah.append(f"{ch}({p:2d}) {op} {k_char}({k:2d}) mod 26 = {c:2d} -> {c_char}")
            idx_k += 1

        return ''.join(hasil), langkah

    @classmethod
    def vigenere_autokey(cls, teks, kunci, mode='enkripsi'):
        teks_olah = cls.bersihkan(teks, hapus_spasi=True)
        kunci_olah = cls.bersihkan(kunci, hapus_spasi=True)
        if not kunci_olah:
            raise ValueError("Kunci tidak boleh kosong!")

        hasil, langkah = [], []
        kunci_dinamis = list(kunci_olah)
        for i, ch in enumerate(teks_olah):
            p = ord(ch) - 65
            k_char = kunci_dinamis[i]
            k = ord(k_char) - 65
            if mode == 'enkripsi':
                c = (p + k) % 26
                res_char = chr(c + 65)
                kunci_dinamis.append(ch)
                langkah.append(f"{ch}({p:2d}) + {k_char}({k:2d}) mod 26 = {c:2d} -> {res_char}")
            else:
                p_dek = (p - k) % 26
                res_char = chr(p_dek + 65)
                kunci_dinamis.append(res_char)
                langkah.append(f"{ch}({p:2d}) - {k_char}({k:2d}) mod 26 = {p_dek:2d} -> {res_char}")
            hasil.append(res_char)

        return ''.join(hasil), langkah

    @classmethod
    def vigenere_runningkey(cls, teks, kunci_panjang, mode='enkripsi'):
        teks_olah = cls.bersihkan(teks, hapus_spasi=True)
        kunci_olah = cls.bersihkan(kunci_panjang, hapus_spasi=True)
        if len(kunci_olah) < len(teks_olah):
            raise ValueError(
                f"Running-Key ({len(kunci_olah)} huruf) tidak boleh lebih pendek dari teks ({len(teks_olah)} huruf)."
            )
        return cls.vigenere_standar(teks_olah, kunci_olah[:len(teks_olah)], mode, hapus_spasi=True)

    @classmethod
    def beaufort(cls, teks, kunci):
        teks_olah = cls.bersihkan(teks, hapus_spasi=True)
        kunci_olah = cls.bersihkan(kunci, hapus_spasi=True)
        if not kunci_olah:
            raise ValueError("Kunci tidak boleh kosong!")

        hasil, langkah = [], []
        for i, ch in enumerate(teks_olah):
            p = ord(ch) - 65
            k_char = kunci_olah[i % len(kunci_olah)]
            k = ord(k_char) - 65
            c = (k - p) % 26
            res_char = chr(c + 65)
            hasil.append(res_char)
            langkah.append(f"K:{k_char}({k:2d}) - P:{ch}({p:2d}) mod 26 = {c:2d} -> {res_char}")

        return ''.join(hasil), langkah

    # --- KRIPTOANALISIS: KASISKI & FREKUENSI ---
    @classmethod
    def analisis_kasiski(cls, cipherteks):
        teks = cls.bersihkan(cipherteks, hapus_spasi=True)
        if len(teks) < 6:
            raise ValueError("Cipherteks terlalu pendek untuk dianalisis (minimal 6 huruf).")

        posisi = defaultdict(list)
        for i in range(len(teks) - 2):
            trigram = teks[i:i+3]
            posisi[trigram].append(i)

        berulang = {k: v for k, v in posisi.items() if len(v) > 1}
        laporan = [f"Total Karakter Dianalisis : {len(teks)} huruf", "=" * 55]

        if not berulang:
            laporan.append("Tidak ditemukan pola 3-huruf (trigram) yang berulang.")
        else:
            laporan.append("1. POLA TRIGRAM BERULANG & JARAKNYA:")
            jarak_semua = []
            for pola, idx_list in berulang.items():
                jarak = [idx_list[i+1] - idx_list[i] for i in range(len(idx_list)-1)]
                jarak_semua.extend(jarak)
                laporan.append(f"   - Pola '{pola}' muncul di indeks {idx_list} -> Jarak: {jarak}")

            faktor_hitung = defaultdict(int)
            for j in jarak_semua:
                for f in range(2, j + 1):
                    if j % f == 0:
                        faktor_hitung[f] += 1

            kandidat = sorted(faktor_hitung.items(), key=lambda x: x[1], reverse=True)[:5]
            laporan.append("\n2. PREDIKSI PANJANG KUNCI (FAKTOR PEMBAGI JARAK):")
            for panjang, frek in kandidat:
                laporan.append(f"   - Panjang Kunci = {panjang:2d} (muncul {frek} kali)")

        # Tambahan Distribusi Frekuensi Huruf
        hitung = Counter(teks)
        top_huruf = hitung.most_common(6)
        laporan.append("\n3. FREKUENSI HURUF TERBANYAK PADA CIPHERTEKS:")
        for h, jml in top_huruf:
            persen = (jml / len(teks)) * 100
            bar = "█" * int(persen)
            laporan.append(f"   - {h} : {jml:2d} kali ({persen:5.1f}%) {bar}")

        return "\n".join(laporan)

    # --- HILL CIPHER N x N (Pemetaan Slide: A=1 .. Y=25, Z=0) ---
    @staticmethod
    def char_to_hill(ch):
        val = ord(ch) - 64
        return 0 if val == 26 else val

    @staticmethod
    def hill_to_char(num):
        num %= 26
        return 'Z' if num == 0 else chr(num + 64)

    @staticmethod
    def mod_inverse(a, m=26):
        a %= m
        for x in range(1, m):
            if (a * x) % m == 1:
                return x
        return None

    @classmethod
    def invers_matriks(cls, M):
        n = len(M)
        aug = [[M[i][j] % 26 for j in range(n)] + [1 if i == j else 0 for j in range(n)] for i in range(n)]
        for col in range(n):
            pivot = next((r for r in range(col, n) if cls.mod_inverse(aug[r][col]) is not None), None)
            if pivot is None:
                raise ValueError("Matriks tidak invertible di mod 26 (determinan tidak koprima dengan 26).")
            aug[col], aug[pivot] = aug[pivot], aug[col]
            inv_p = cls.mod_inverse(aug[col][col])
            for j in range(2 * n):
                aug[col][j] = (aug[col][j] * inv_p) % 26
            for r in range(n):
                if r != col:
                    faktor = aug[r][col]
                    for j in range(2 * n):
                        aug[r][j] = (aug[r][j] - faktor * aug[col][j]) % 26
        return [row[n:] for row in aug]

    @classmethod
    def hill_cipher(cls, teks, matriks, mode='enkripsi'):
        n = len(matriks)
        teks_olah = cls.bersihkan(teks, hapus_spasi=True)
        if not teks_olah:
            raise ValueError("Teks masukan tidak boleh kosong!")

        sisa = len(teks_olah) % n
        if sisa != 0:
            teks_olah += teks_olah[-1] * (n - sisa)

        matriks_inv = cls.invers_matriks(matriks)
        K_aktif = matriks if mode == 'enkripsi' else matriks_inv

        hasil, langkah = [], []
        for i in range(0, len(teks_olah), n):
            blok = teks_olah[i:i+n]
            vec_in = [cls.char_to_hill(c) for c in blok]
            vec_out = [sum(K_aktif[r][c] * vec_in[c] for c in range(n)) % 26 for r in range(n)]
            blok_out = ''.join(cls.hill_to_char(v) for v in vec_out)
            hasil.append(blok_out)
            langkah.append(f"Blok '{blok}' {vec_in} -> {vec_out} '{blok_out}'")

        return ''.join(hasil), matriks_inv, langkah


# =====================================================================
# ANTARMUKA GRAFIS LENGKAP (4 TAB INTERAKTIF)
# =====================================================================

class AplikasiKriptografi:
    def __init__(self, root):
        self.root = root
        self.root.title("Laboratorium Kriptografi Klasik - Vigenère & Hill Cipher")
        self.root.geometry("880x660")
        self.root.configure(padx=12, pady=12)
        self.hasil_terakhir_vig = ""
        self.hasil_terakhir_hill = ""

        notebook = ttk.Notebook(root)
        notebook.pack(fill="both", expand=True)

        self.tab_vig = ttk.Frame(notebook, padding=10)
        self.tab_hill = ttk.Frame(notebook, padding=10)
        self.tab_kasiski = ttk.Frame(notebook, padding=10)
        self.tab_tabel = ttk.Frame(notebook, padding=10)

        notebook.add(self.tab_vig, text="1. Vigenère & Varian")
        notebook.add(self.tab_hill, text="2. Hill Cipher (2x2 & 3x3)")
        notebook.add(self.tab_kasiski, text="3. Kriptoanalisis (Kasiski)")
        notebook.add(self.tab_tabel, text="4. Referensi Tabel & Bujursangkar")

        self._init_tab_vigenere()
        self._init_tab_hill()
        self._init_tab_kasiski()
        self._init_tab_tabel()

    # ---------------- TAB 1: VIGENERE ----------------
    def _init_tab_vigenere(self):
        top = ttk.LabelFrame(self.tab_vig, text="Konfigurasi Vigenère", padding=8)
        top.pack(fill="x", pady=4)

        ttk.Label(top, text="Metode:").grid(row=0, column=0, sticky="w")
        self.var_metode = tk.StringVar(value="Standard Vigenère")
        ttk.Combobox(
            top, textvariable=self.var_metode, state="readonly", width=22,
            values=["Standard Vigenère", "Auto-Key Vigenère", "Running-Key Vigenère", "Beaufort Cipher"]
        ).grid(row=0, column=1, padx=6, sticky="w")

        self.var_spasi = tk.BooleanVar(value=False)
        ttk.Checkbutton(top, text="Pertahankan Spasi", variable=self.var_spasi).grid(row=0, column=2, padx=8)

        ttk.Label(top, text="Preset Slide:").grid(row=0, column=3, padx=(12, 4))
        self.var_preset_vig = tk.StringVar(value="Pilih Contoh Slide...")
        cb_preset = ttk.Combobox(
            top, textvariable=self.var_preset_vig, state="readonly", width=26,
            values=[
                "1. Standar (LAMPION)",
                "2. Dengan Spasi (KEY)",
                "3. Paragraf Lumpur (langitbiru)",
                "4. Auto-Key (INDO)",
                "5. Running-Key (UUD 1945)",
                "6. Beaufort (FULLMOON)"
            ]
        )
        cb_preset.grid(row=0, column=4)
        cb_preset.bind("<<ComboboxSelected>>", self._terapkan_preset_vig)

        ttk.Label(top, text="Kunci:").grid(row=1, column=0, sticky="w", pady=(8, 0))
        self.ent_kunci_vig = ttk.Entry(top, width=55)
        self.ent_kunci_vig.insert(0, "LAMPION")
        self.ent_kunci_vig.grid(row=1, column=1, columnspan=4, padx=6, pady=(8, 0), sticky="w")

        hdr_in = ttk.Frame(self.tab_vig)
        hdr_in.pack(fill="x", pady=(6, 2))
        ttk.Label(hdr_in, text="Teks Masukan:").pack(side="left")
        ttk.Button(hdr_in, text="Muat dari File .TXT", command=self._muat_file_vig).pack(side="right")

        self.txt_in_vig = scrolledtext.ScrolledText(self.tab_vig, height=4)
        self.txt_in_vig.insert("1.0", "KRIPTOGRAFIKLASIKDENGANCIPHERALFABETMAJEMUK")
        self.txt_in_vig.pack(fill="x")

        bar_btn = ttk.Frame(self.tab_vig)
        bar_btn.pack(fill="x", pady=6)
        ttk.Button(bar_btn, text="Enkripsi", command=lambda: self._run_vig('enkripsi')).pack(side="left", padx=3)
        ttk.Button(bar_btn, text="Dekripsi", command=lambda: self._run_vig('dekripsi')).pack(side="left", padx=3)
        ttk.Button(bar_btn, text="Tukar Hasil ke Input ↑", command=self._tukar_vig).pack(side="left", padx=10)
        ttk.Button(bar_btn, text="Salin Hasil", command=lambda: self._salin_hasil(self.hasil_terakhir_vig)).pack(side="left", padx=3)
        ttk.Button(bar_btn, text="Simpan Log ke .TXT", command=lambda: self._simpan_txt(self.txt_out_vig)).pack(side="right", padx=3)

        ttk.Label(self.tab_vig, text="Hasil & Rincian Perhitungan:").pack(anchor="w", pady=(4, 2))
        self.txt_out_vig = scrolledtext.ScrolledText(self.tab_vig, height=13, font=("Consolas", 10))
        self.txt_out_vig.pack(fill="both", expand=True)

    def _muat_file_vig(self):
        path = filedialog.askopenfilename(filetypes=[("Text Files", "*.txt")])
        if path:
            with open(path, "r", encoding="utf-8") as f:
                self.txt_in_vig.delete("1.0", tk.END)
                self.txt_in_vig.insert("1.0", f.read())

    def _tukar_vig(self):
        if not self.hasil_terakhir_vig:
            messagebox.showwarning("Kosong", "Belum ada hasil untuk dipindahkan ke masukan.")
            return
        self.txt_in_vig.delete("1.0", tk.END)
        self.txt_in_vig.insert("1.0", self.hasil_terakhir_vig)

    def _terapkan_preset_vig(self, _event=None):
        pilihan = self.var_preset_vig.get()
        self.ent_kunci_vig.delete(0, tk.END)
        self.txt_in_vig.delete("1.0", tk.END)
        if pilihan.startswith("1."):
            self.var_metode.set("Standard Vigenère")
            self.var_spasi.set(False)
            self.ent_kunci_vig.insert(0, "LAMPION")
            self.txt_in_vig.insert("1.0", "KRIPTOGRAFIKLASIKDENGANCIPHERALFABETMAJEMUK")
        elif pilihan.startswith("2."):
            self.var_metode.set("Standard Vigenère")
            self.var_spasi.set(True)
            self.ent_kunci_vig.insert(0, "KEY")
            self.txt_in_vig.insert("1.0", "SHE SELLS SEA SHELLS BY THE SEASHORE")
        elif pilihan.startswith("3."):
            self.var_metode.set("Standard Vigenère")
            self.var_spasi.set(True)
            self.ent_kunci_vig.insert(0, "langitbiru")
            self.txt_in_vig.insert("1.0", "Jawa Timur Bakal Tenggelam. Semburan lumpur panas di desa Porong, Sidoarjo, Jawa Timur belum juga berakhir.")
        elif pilihan.startswith("4."):
            self.var_metode.set("Auto-Key Vigenère")
            self.var_spasi.set(False)
            self.ent_kunci_vig.insert(0, "INDO")
            self.txt_in_vig.insert("1.0", "NEGARA PENGHASIL MINYAK")
        elif pilihan.startswith("5."):
            self.var_metode.set("Running-Key Vigenère")
            self.var_spasi.set(False)
            self.ent_kunci_vig.insert(0, "KEMANUSIAANYANGADILDANBERADAB")
            self.txt_in_vig.insert("1.0", "NEGARA PENGHASIL MINYAK")
        elif pilihan.startswith("6."):
            self.var_metode.set("Beaufort Cipher")
            self.var_spasi.set(False)
            self.ent_kunci_vig.insert(0, "FULLMOON")
            self.txt_in_vig.insert("1.0", "MEETMEATMIDNIGHT")

    def _run_vig(self, mode):
        metode = self.var_metode.get()
        teks = self.txt_in_vig.get("1.0", tk.END).strip()
        kunci = self.ent_kunci_vig.get().strip()
        try:
            if metode == "Standard Vigenère":
                hasil, langkah = KriptografiEngine.vigenere_standar(
                    teks, kunci, mode, hapus_spasi=not self.var_spasi.get()
                )
            elif metode == "Auto-Key Vigenère":
                hasil, langkah = KriptografiEngine.vigenere_autokey(teks, kunci, mode)
            elif metode == "Running-Key Vigenère":
                hasil, langkah = KriptografiEngine.vigenere_runningkey(teks, kunci, mode)
            else:
                hasil, langkah = KriptografiEngine.beaufort(teks, kunci)

            self.hasil_terakhir_vig = hasil
            laporan = (
                f"METODE : {metode} ({mode.upper()})\n"
                f"KUNCI  : {kunci.upper()}\n"
                f"HASIL  : {hasil}\n"
                + "=" * 58 + "\n"
                + "RINCIAN PERHITUNGAN:\n" + "\n".join(langkah)
            )
            self.txt_out_vig.delete("1.0", tk.END)
            self.txt_out_vig.insert("1.0", laporan)
        except Exception as e:
            messagebox.showerror("Error", str(e))

    # ---------------- TAB 2: HILL CIPHER ----------------
    def _init_tab_hill(self):
        frame_mat = ttk.Frame(self.tab_hill)
        frame_mat.pack(fill="x", pady=4)

        lf_k = ttk.LabelFrame(frame_mat, text="Matriks Kunci K (Pisah spasi)", padding=8)
        lf_k.pack(side="left", fill="both", expand=True, padx=(0, 4))
        self.txt_k = tk.Text(lf_k, height=4, width=22, font=("Consolas", 11))
        self.txt_k.insert("1.0", "5 6\n2 3")
        self.txt_k.pack(fill="both", expand=True)

        lf_kinv = ttk.LabelFrame(frame_mat, text="Matriks Invers K⁻¹ (Mod 26)", padding=8)
        lf_kinv.pack(side="right", fill="both", expand=True, padx=(4, 0))
        self.txt_kinv = tk.Text(lf_kinv, height=4, width=22, font=("Consolas", 11), state="disabled")
        self.txt_kinv.pack(fill="both", expand=True)

        ttk.Label(self.tab_hill, text="Teks Masukan (Aturan Slide: A=1..Y=25, Z=0):").pack(anchor="w", pady=(6, 2))
        self.ent_in_hill = ttk.Entry(self.tab_hill)
        self.ent_in_hill.insert(0, "STRIKE NOW")
        self.ent_in_hill.pack(fill="x")

        bar_btn = ttk.Frame(self.tab_hill)
        bar_btn.pack(fill="x", pady=6)
        ttk.Button(bar_btn, text="Enkripsi Hill", command=lambda: self._run_hill('enkripsi')).pack(side="left", padx=3)
        ttk.Button(bar_btn, text="Dekripsi Hill", command=lambda: self._run_hill('dekripsi')).pack(side="left", padx=3)
        ttk.Button(bar_btn, text="Tukar Hasil ke Input ↑", command=self._tukar_hill).pack(side="left", padx=8)
        ttk.Button(bar_btn, text="Preset Slide (2x2)", command=self._preset_hill_2x2).pack(side="left", padx=4)
        ttk.Button(bar_btn, text="Preset Matriks 3x3", command=self._preset_hill_3x3).pack(side="left", padx=4)
        ttk.Button(bar_btn, text="Simpan Log ke .TXT", command=lambda: self._simpan_txt(self.txt_out_hill)).pack(side="right", padx=3)

        ttk.Label(self.tab_hill, text="Hasil & Rincian Perhitungan Blok:").pack(anchor="w", pady=(4, 2))
        self.txt_out_hill = scrolledtext.ScrolledText(self.tab_hill, height=13, font=("Consolas", 10))
        self.txt_out_hill.pack(fill="both", expand=True)

    def _tukar_hill(self):
        if not self.hasil_terakhir_hill:
            messagebox.showwarning("Kosong", "Belum ada hasil untuk dipindahkan ke masukan.")
            return
        self.ent_in_hill.delete(0, tk.END)
        self.ent_in_hill.insert(0, self.hasil_terakhir_hill)

    def _preset_hill_2x2(self):
        self.txt_k.delete("1.0", tk.END)
        self.txt_k.insert("1.0", "5 6\n2 3")
        self.ent_in_hill.delete(0, tk.END)
        self.ent_in_hill.insert(0, "STRIKE NOW")

    def _preset_hill_3x3(self):
        self.txt_k.delete("1.0", tk.END)
        self.txt_k.insert("1.0", "6 24 1\n13 16 10\n20 17 15")
        self.ent_in_hill.delete(0, tk.END)
        self.ent_in_hill.insert(0, "TEKNIK INFORMATIKA")

    def _run_hill(self, mode):
        try:
            baris = [b.strip() for b in self.txt_k.get("1.0", tk.END).strip().splitlines() if b.strip()]
            matriks = [[int(x) for x in b.split()] for b in baris]
            n = len(matriks)
            if n < 2 or any(len(r) != n for r in matriks):
                raise ValueError("Matriks kunci harus persegi (n x n), minimal 2x2.")

            teks = self.ent_in_hill.get()
            hasil, k_inv, langkah = KriptografiEngine.hill_cipher(teks, matriks, mode)
            self.hasil_terakhir_hill = hasil

            self.txt_kinv.config(state="normal")
            self.txt_kinv.delete("1.0", tk.END)
            self.txt_kinv.insert("1.0", "\n".join(" ".join(f"{v:2d}" for v in row) for row in k_inv))
            self.txt_kinv.config(state="disabled")

            laporan = (
                f"METODE : Hill Cipher {n}x{n} ({mode.upper()})\n"
                f"HASIL  : {hasil}\n"
                + "=" * 58 + "\n"
                + "RINCIAN PER BLOK:\n" + "\n".join(langkah)
            )
            self.txt_out_hill.delete("1.0", tk.END)
            self.txt_out_hill.insert("1.0", laporan)
        except Exception as e:
            messagebox.showerror("Error", str(e))

    # ---------------- TAB 3: KASISKI ----------------
    def _init_tab_kasiski(self):
        ttk.Label(
            self.tab_kasiski,
            text="Masukkan Cipherteks Vigenère untuk menebak panjang kunci (Metode Kasiski & Frekuensi Huruf):"
        ).pack(anchor="w", pady=(4, 2))
        self.txt_in_kas = scrolledtext.ScrolledText(self.tab_kasiski, height=5)
        self.txt_in_kas.insert("1.0", "VRUEBCTCARXSZNDIWSMBTLNOXXVRCAXUIPREMMYMAHV")
        self.txt_in_kas.pack(fill="x")

        bar_kas = ttk.Frame(self.tab_kasiski)
        bar_kas.pack(fill="x", pady=6)
        ttk.Button(bar_kas, text="Analisis Panjang Kunci (Kasiski)", command=self._run_kasiski).pack(side="left", padx=3)
        ttk.Button(bar_kas, text="Ambil Cipherteks dari Tab 1", command=self._ambil_dari_vig).pack(side="left", padx=6)

        self.txt_out_kas = scrolledtext.ScrolledText(self.tab_kasiski, height=15, font=("Consolas", 10))
        self.txt_out_kas.pack(fill="both", expand=True)

    def _ambil_dari_vig(self):
        if not self.hasil_terakhir_vig:
            messagebox.showwarning("Kosong", "Belum ada hasil enkripsi di Tab 1.")
            return
        self.txt_in_kas.delete("1.0", tk.END)
        self.txt_in_kas.insert("1.0", self.hasil_terakhir_vig)

    def _run_kasiski(self):
        try:
            teks = self.txt_in_kas.get("1.0", tk.END).strip()
            laporan = KriptografiEngine.analisis_kasiski(teks)
            self.txt_out_kas.delete("1.0", tk.END)
            self.txt_out_kas.insert("1.0", laporan)
        except Exception as e:
            messagebox.showerror("Error", str(e))

    # ---------------- TAB 4: REFERENSI TABEL ----------------
    def _init_tab_tabel(self):
        ttk.Label(
            self.tab_tabel,
            text="Bujursangkar Vigenère (A=0..Z=25) & Pemetaan Hill Cipher (A=1..Y=25, Z=0):"
        ).pack(anchor="w", pady=(2, 4))

        txt_ref = scrolledtext.ScrolledText(self.tab_tabel, font=("Consolas", 9))
        txt_ref.pack(fill="both", expand=True)

        alfabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        garis = ["=== 1. TABEL PEMETAAN ANGKA ==="]
        garis.append("Huruf    : " + " ".join(f"{c:>2}" for c in alfabet))
        garis.append("Vigenère : " + " ".join(f"{i:2d}" for i in range(26)))
        garis.append("Hill     : " + " ".join(f"{(i+1)%26:2d}" for i in range(26)))
        garis.append("\n=== 2. BUJURSANGKAR VIGENÈRE (TABULA RECTA) ===")
        garis.append("    | " + " ".join(alfabet))
        garis.append("----+" + "-" * 52)
        for i, ch in enumerate(alfabet):
            geser = alfabet[i:] + alfabet[:i]
            garis.append(f" {ch}  | " + " ".join(geser))

        txt_ref.insert("1.0", "\n".join(garis))
        txt_ref.config(state="disabled")

    # ---------------- UTILITAS ----------------
    def _salin_hasil(self, teks_hasil):
        if not teks_hasil:
            messagebox.showwarning("Kosong", "Belum ada hasil yang bisa disalin.")
            return
        self.root.clipboard_clear()
        self.root.clipboard_append(teks_hasil)
        messagebox.showinfo("Disalin", f"Teks '{teks_hasil}' berhasil disalin ke clipboard!")

    def _simpan_txt(self, widget_teks):
        isi = widget_teks.get("1.0", tk.END).strip()
        if not isi:
            messagebox.showwarning("Kosong", "Belum ada hasil perhitungan untuk disimpan.")
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            initialfile=f"Laporan_Kriptografi_{datetime.now().strftime('%Y%m%d_%H%M')}.txt",
            filetypes=[("Text Files", "*.txt")]
        )
        if path:
            with open(path, "w", encoding="utf-8") as f:
                f.write(isi)
            messagebox.showinfo("Tersimpan", f"Log perhitungan berhasil disimpan ke:\n{path}")

if __name__ == "__main__":
    root = tk.Tk()
    AplikasiKriptografi(root)
    root.mainloop()