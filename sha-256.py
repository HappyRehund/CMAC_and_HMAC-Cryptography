import os
import argparse

# Fungsi pembantu untuk operasi bitwise 32-bit
def ROTR(x, n):
    """Rotasi kanan bit x sebanyak n posisi dalam word 32-bit."""
    return ((x >> n) | (x << (32 - n))) & 0xFFFFFFFF

def SHR(x, n):
    """Shift kanan bit x sebanyak n posisi dalam word 32-bit."""
    return (x >> n) & 0xFFFFFFFF

# Fungsi logika SHA-256
def Ch(x, y, z):
    """Fungsi Choice."""
    return (x & y) ^ (~x & z) & 0xFFFFFFFF

def Maj(x, y, z):
    """Fungsi Majority."""
    return (x & y) ^ (x & z) ^ (y & z) & 0xFFFFFFFF

def Sigma0_a(x):
    """Fungsi Sigma0 untuk variabel 'a'."""
    return (ROTR(x, 2) ^ ROTR(x, 13) ^ ROTR(x, 22)) & 0xFFFFFFFF

def Sigma1_e(x):
    """Fungsi Sigma1 untuk variabel 'e'."""
    return (ROTR(x, 6) ^ ROTR(x, 11) ^ ROTR(x, 25)) & 0xFFFFFFFF

# Fungsi untuk message schedule
def sigma0_msg(x):
    """Fungsi sigma0 untuk message schedule."""
    return (ROTR(x, 7) ^ ROTR(x, 18) ^ SHR(x, 3)) & 0xFFFFFFFF

def sigma1_msg(x):
    """Fungsi sigma1 untuk message schedule."""
    return (ROTR(x, 17) ^ ROTR(x, 19) ^ SHR(x, 10)) & 0xFFFFFFFF

# Nilai hash awal (H_initial) - 32 bit pertama dari bagian pecahan akar kuadrat dari 8 bilangan prima pertama (2..19)
H_INITIAL = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
]

# Konstanta putaran (K) - 32 bit pertama dari bagian pecahan akar pangkat tiga dari 64 bilangan prima pertama (2..311)
K_CONSTANTS = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
]

def _pad_message(message_bytes):
    """Melakukan padding pada pesan sesuai standar SHA-256."""
    original_length_bits = len(message_bytes) * 8
    
    # Tambahkan bit '1' (byte 0x80)
    padded_message = message_bytes + b'\x80'
    
    # Tambahkan bit '0' (byte 0x00) hingga panjang pesan dalam bit adalah 448 (mod 512)
    # Artinya, panjang pesan dalam byte % 64 == 56
    while len(padded_message) % 64 != 56:
        padded_message += b'\x00'
        
    # Tambahkan panjang asli pesan (dalam bit) sebagai integer 64-bit big-endian
    padded_message += original_length_bits.to_bytes(8, byteorder='big')
    
    return padded_message

def _process_chunk(chunk, h_current):
    """Memproses satu blok 512-bit dari pesan."""
    # Pecah blok menjadi 16 word 32-bit (big-endian)
    w = [0] * 64
    for i in range(16):
        w[i] = int.from_bytes(chunk[i*4:i*4+4], byteorder='big')

    # Expand 16 word menjadi 64 word untuk message schedule
    for i in range(16, 64):
        s0 = sigma0_msg(w[i-15])
        s1 = sigma1_msg(w[i-2])
        w[i] = (w[i-16] + s0 + w[i-7] + s1) & 0xFFFFFFFF # Penjumlahan modulo 2^32
        
    # Inisialisasi variabel kerja dengan nilai hash saat ini
    a, b, c, d, e, f, g, h = h_current
    
    # Loop kompresi utama sebanyak 64 putaran
    for i in range(64):
        S1 = Sigma1_e(e)
        ch_val = Ch(e, f, g)
        # Penjumlahan modulo 2^32
        temp1 = (h + S1 + ch_val + K_CONSTANTS[i] + w[i]) & 0xFFFFFFFF
        
        S0 = Sigma0_a(a)
        maj_val = Maj(a, b, c)
        # Penjumlahan modulo 2^32
        temp2 = (S0 + maj_val) & 0xFFFFFFFF
        
        h = g
        g = f
        f = e
        e = (d + temp1) & 0xFFFFFFFF # Penjumlahan modulo 2^32
        d = c
        c = b
        b = a
        a = (temp1 + temp2) & 0xFFFFFFFF # Penjumlahan modulo 2^32
        
    # Hitung nilai hash intermediet baru
    h_new = [0] * 8
    h_new[0] = (h_current[0] + a) & 0xFFFFFFFF
    h_new[1] = (h_current[1] + b) & 0xFFFFFFFF
    h_new[2] = (h_current[2] + c) & 0xFFFFFFFF
    h_new[3] = (h_current[3] + d) & 0xFFFFFFFF
    h_new[4] = (h_current[4] + e) & 0xFFFFFFFF
    h_new[5] = (h_current[5] + f) & 0xFFFFFFFF
    h_new[6] = (h_current[6] + g) & 0xFFFFFFFF
    h_new[7] = (h_current[7] + h) & 0xFFFFFFFF
    
    return h_new

def sha256_manual(data_bytes):
    """Menghitung SHA-256 hash dari data bytes secara manual."""
    padded_data = _pad_message(data_bytes)
    
    # Inisialisasi nilai hash dengan H_INITIAL (buat salinan yang bisa diubah)
    h_vars = list(H_INITIAL) 
    
    num_chunks = len(padded_data) // 64
    for i in range(num_chunks):
        chunk = padded_data[i*64 : (i+1)*64]
        h_vars = _process_chunk(chunk, h_vars)
        
    # Gabungkan nilai-nilai hash menjadi satu string heksadesimal
    final_hash_hex = ''.join(f'{val:08x}' for val in h_vars)
    return final_hash_hex

# Fungsi untuk Integritas File 
def compute_and_store_hash_manual(filepath, hash_filename_suffix=".sha256_manual"):
    """Membaca file, menghitung hash SHA-256 manual, dan menyimpannya."""
    try:
        with open(filepath, 'rb') as f:
            file_bytes = f.read()
        
        file_hash = sha256_manual(file_bytes)
        
        hash_filepath = filepath + hash_filename_suffix
        with open(hash_filepath, 'w') as hf:
            hf.write(file_hash)
        print(f"Hash SHA-256 (manual) untuk '{filepath}' telah dihitung dan disimpan ke '{hash_filepath}'")
        print(f"Hash: {file_hash}")
        return file_hash, hash_filepath
    except FileNotFoundError:
        print(f"Error: File '{filepath}' tidak ditemukan.")
        return None, None
    except Exception as e:
        print(f"Error saat menghitung atau menyimpan hash: {e}")
        return None, None

def verify_file_integrity_manual(filepath, hash_filename_suffix=".sha256_manual"):
    """Memverifikasi integritas file dengan membandingkan hash saat ini dengan hash yang tersimpan."""
    try:
        # Hitung hash file saat ini
        with open(filepath, 'rb') as f:
            current_file_bytes = f.read()
        current_hash = sha256_manual(current_file_bytes)
        
        # Baca hash yang tersimpan
        hash_filepath = filepath + hash_filename_suffix
        if not os.path.exists(hash_filepath):
            print(f"Error: File hash '{hash_filepath}' tidak ditemukan. Harap hitung dan simpan hash terlebih dahulu.")
            return False
            
        with open(hash_filepath, 'r') as hf:
            stored_hash = hf.read().strip()
            
        print(f"\nMemverifikasi integritas file: '{filepath}'")
        print(f"Hash Tersimpan : {stored_hash}")
        print(f"Hash Saat Ini   : {current_hash}")
        
        if current_hash == stored_hash:
            print("hasil: Integritas file aman. Tidak ada perubahan terdeteksi.")
            return True
        else:
            print("hasil: Integritas file rusak. File telah dimodifikasi!")
            return False
            
    except FileNotFoundError:
        print(f"Error: File '{filepath}' tidak ditemukan untuk verifikasi.")
        return False
    except Exception as e:
        print(f"Error saat verifikasi integritas: {e}")
        return False

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Pemeriksa Integritas File menggunakan SHA-256 Manual.")
    parser.add_argument("mode", choices=['store', 'verify'], help="Mode operasi: 'store' untuk menghitung dan menyimpan hash, 'verify' untuk memverifikasi integritas file.")
    parser.add_argument("filepath", help="Path ke file yang akan diproses.")
    
    args = parser.parse_args()
    
    if args.mode == 'store':
        compute_and_store_hash_manual(args.filepath)
    elif args.mode == 'verify':
        verify_file_integrity_manual(args.filepath)