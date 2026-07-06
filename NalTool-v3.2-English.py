# NalTool - TasKin Made - 3.2

import os
import sys
import base64
import hashlib
import hmac
import getpass
import time
import struct
from pathlib import Path
from datetime import datetime

# ==================== Version Info ====================
VERSION = "3.2"
AUTHOR = "TasKin"
EMAIL = "tnailkogns@hotmail.com"
MAGIC_HEADER = b'NALT'  # File header magic number for identification
HEADER_VERSION = 1      # File format version

# ==================== Platform Detection ====================
IS_WINDOWS = sys.platform == 'win32'
IS_UNIX = sys.platform in ('linux', 'darwin', 'cygwin', 'freebsd')

# ==================== Cross-platform Password Input ====================
def get_password_with_asterisk(prompt='Enter key: '):
    """Password input showing * characters, cross-platform support"""
    if IS_WINDOWS:
        import msvcrt
        print(prompt, end='', flush=True)
        password = []
        while True:
            ch = msvcrt.getch()
            if ch in (b'\r', b'\n'):
                print()
                break
            elif ch == b'\x08':  # Backspace
                if password:
                    password.pop()
                    sys.stdout.write('\b \b')
                    sys.stdout.flush()
            elif ch == b'\x03':  # Ctrl+C
                raise KeyboardInterrupt
            elif ch == b'\x1b':  # ESC
                raise KeyboardInterrupt
            else:
                try:
                    char = ch.decode('utf-8')
                    password.append(char)
                    sys.stdout.write('*')
                    sys.stdout.flush()
                except UnicodeDecodeError:
                    pass
        return ''.join(password)
    else:
        # Unix/Linux/macOS using termios
        import termios
        import tty
        try:
            fd = sys.stdin.fileno()
            old_settings = termios.tcgetattr(fd)
            try:
                tty.setraw(sys.stdin.fileno())
                print(prompt, end='', flush=True)
                password = []
                while True:
                    ch = sys.stdin.read(1)
                    if ch in ('\r', '\n'):
                        sys.stdout.write('\r\n')
                        sys.stdout.flush()
                        break
                    elif ch == '\x7f' or ch == '\x08':  # Backspace
                        if password:
                            password.pop()
                            sys.stdout.write('\b \b')
                            sys.stdout.flush()
                    elif ch == '\x03':  # Ctrl+C
                        raise KeyboardInterrupt
                    elif ch == '\x1b':  # ESC
                        raise KeyboardInterrupt
                    else:
                        password.append(ch)
                        sys.stdout.write('*')
                        sys.stdout.flush()
                return ''.join(password)
            finally:
                termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)
        except Exception:
            return getpass.getpass(prompt)

# ==================== Get Script Directory ====================
def get_script_directory():
    """Get the directory where the NalTool script is located"""
    return os.path.dirname(os.path.abspath(__file__))

# ==================== Base91 Codec ====================
B91_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!#$%&()*+,./:;<=>?@[]^_`{|}~"'

def b91encode(data):
    """Base91 encoding"""
    if not data:
        return ''
    b, n, out = 0, 0, []
    for byte in data:
        b |= (byte << n)
        n += 8
        if n > 13:
            v = b & 8191
            if v > 88:
                b >>= 13
                n -= 13
            else:
                v = b & 16383
                b >>= 14
                n -= 14
            out.append(B91_ALPHABET[v % 91])
            out.append(B91_ALPHABET[v // 91])
    if n:
        out.append(B91_ALPHABET[b % 91])
        if n > 7 or b > 90:
            out.append(B91_ALPHABET[b // 91])
    return ''.join(out)

def b91decode(s):
    """Base91 decoding"""
    if not s:
        return b''
    v, b, n = -1, 0, 0
    out = bytearray()
    for ch in s:
        try:
            c = B91_ALPHABET.index(ch)
        except ValueError:
            continue
        if v < 0:
            v = c
        else:
            v += c * 91
            b |= (v << n)
            n += 13 if (v & 8191) > 88 else 14
            while n > 7:
                out.append(b & 255)
                b >>= 8
                n -= 8
            v = -1
    if v != -1:
        b |= (v << n)
        out.append(b & 255)
    return bytes(out)

# ==================== Core Encryption ====================
def _derive_key(password, salt, iterations=600000, dklen=32):
    """PBKDF2-HMAC-SHA256 key derivation"""
    return hashlib.pbkdf2_hmac(
        'sha256',
        password.encode('utf-8'),
        salt,
        iterations,
        dklen
    )

def _generate_keystream(key, iv, counter, length):
    """Generate CTR mode keystream using HMAC-SHA256"""
    keystream = bytearray()
    current_counter = counter

    while len(keystream) < length:
        counter_bytes = current_counter.to_bytes(8, 'big')
        input_data = iv + counter_bytes
        block = hmac.new(key, input_data, hashlib.sha256).digest()
        keystream.extend(block)
        current_counter += 1

    return bytes(keystream[:length])

def encrypt_text(text, password):
    """Encrypt text → Base91 string (with HMAC authentication)"""
    if not text:
        raise ValueError('Text cannot be empty')
    if not password:
        raise ValueError('Key cannot be empty')
    
    salt = os.urandom(16)
    iv = os.urandom(16)
    
    enc_key = _derive_key(password, salt, dklen=32)
    mac_key = _derive_key(password, salt + b'auth', dklen=32)
    
    plaintext = text.encode('utf-8')
    ciphertext = bytearray()
    
    for i in range(0, len(plaintext), 16):
        block = plaintext[i:i+16]
        keystream = _generate_keystream(enc_key, iv, i // 16, len(block))
        ciphertext.extend(b ^ k for b, k in zip(block, keystream))
    
    ciphertext = bytes(ciphertext)
    mac = hmac.new(mac_key, ciphertext, hashlib.sha256).digest()
    
    combined = salt + iv + mac + ciphertext
    return b91encode(combined)

def decrypt_text(encrypted, password):
    """Decrypt text from Base91 string (with HMAC verification)"""
    if not encrypted:
        raise ValueError('Ciphertext cannot be empty')
    if not password:
        raise ValueError('Key cannot be empty')
    
    try:
        data = b91decode(encrypted)
        if len(data) < 64:  # salt(16) + iv(16) + mac(32)
            raise ValueError('Data corrupted: length less than 64 bytes')
        
        salt = data[:16]
        iv = data[16:32]
        mac = data[32:64]
        ciphertext = data[64:]
        
        if not ciphertext:
            raise ValueError('Data corrupted: ciphertext is empty')
        
        enc_key = _derive_key(password, salt, dklen=32)
        mac_key = _derive_key(password, salt + b'auth', dklen=32)
        
        # Verify HMAC
        expected_mac = hmac.new(mac_key, ciphertext, hashlib.sha256).digest()
        if not hmac.compare_digest(mac, expected_mac):
            raise ValueError('Authentication failed: wrong key or data tampered')
        
        plaintext = bytearray()
        for i in range(0, len(ciphertext), 16):
            block = ciphertext[i:i+16]
            keystream = _generate_keystream(enc_key, iv, i // 16, len(block))
            plaintext.extend(b ^ k for b, k in zip(block, keystream))
        
        return plaintext.decode('utf-8')
        
    except UnicodeDecodeError:
        raise ValueError('Decryption failed: wrong key or corrupted data')
    except ValueError as e:
        if 'Authentication failed' in str(e):
            raise
        raise ValueError(f'Decryption failed: {str(e)}')
    except Exception as e:
        raise ValueError(f'Decryption failed: {str(e)}')

# ==================== File Processing (Chunked Encryption, Optimized) ====================
def encrypt_file(input_path, output_path, password):
    """
    Encrypt file (chunked processing, supports large files)
    Format: [MAGIC(4)][VERSION(1)][salt(16)][iv(16)][mac(32)][encrypted_chunks...]
    Uses incremental HMAC, memory-friendly
    """
    if not os.path.exists(input_path):
        raise FileNotFoundError(f'File not found: {input_path}')
    if not password:
        raise ValueError('Key cannot be empty')
    
    file_size = os.path.getsize(input_path)
    if file_size == 0:
        raise ValueError('File is empty, cannot encrypt')
    
    salt = os.urandom(16)
    iv = os.urandom(16)
    
    enc_key = _derive_key(password, salt, dklen=32)
    mac_key = _derive_key(password, salt + b'auth', dklen=32)
    
    chunk_size = 64 * 1024  # 64KB
    
    with open(input_path, 'rb') as f_in, open(output_path, 'wb') as f_out:
        # Write file header: magic number + version
        f_out.write(MAGIC_HEADER)
        f_out.write(struct.pack('>B', HEADER_VERSION))
        
        # Write salt and iv
        f_out.write(salt)
        f_out.write(iv)
        
        # Reserve space for MAC
        mac_pos = f_out.tell()
        f_out.write(b'\x00' * 32)
        
        # Use incremental HMAC, no need to store all ciphertext
        mac_ctx = hmac.new(mac_key, digestmod=hashlib.sha256)
        chunk_index = 0
        
        while True:
            chunk = f_in.read(chunk_size)
            if not chunk:
                break
            
            keystream = _generate_keystream(enc_key, iv, chunk_index, len(chunk))
            encrypted_chunk = bytes(b ^ k for b, k in zip(chunk, keystream))
            
            # Write chunk length and encrypted data
            f_out.write(struct.pack('>I', len(encrypted_chunk)))
            f_out.write(encrypted_chunk)
            
            # Update HMAC
            mac_ctx.update(encrypted_chunk)
            chunk_index += 1
        
        # Calculate and write MAC
        mac = mac_ctx.digest()
        f_out.seek(mac_pos)
        f_out.write(mac)
        
        # Ensure file pointer at end
        f_out.seek(0, os.SEEK_END)

def decrypt_file(input_path, output_path, password, progress_callback=None):
    """
    Decrypt file (streaming write, memory-friendly)

    Args:
        input_path: Path to encrypted file
        output_path: Output file path
        password: Decryption key
        progress_callback: Optional progress callback function (current, total)
    """
    if not os.path.exists(input_path):
        raise FileNotFoundError(f'File not found: {input_path}')
    if not password:
        raise ValueError('Key cannot be empty')

    file_size = os.path.getsize(input_path)
    if file_size < 4 + 1 + 16 + 16 + 32:
        raise ValueError('File corrupted: incomplete header')

    with open(input_path, 'rb') as f_in:
        # Read and verify file header
        magic = f_in.read(4)
        if magic != MAGIC_HEADER:
            raise ValueError('File corrupted: invalid file format')

        version_bytes = f_in.read(1)
        if not version_bytes:
            raise ValueError('File corrupted: cannot read version')
        version = struct.unpack('>B', version_bytes)[0]
        if version != HEADER_VERSION:
            raise ValueError(f'Unsupported version: {version}')

        salt = f_in.read(16)
        if len(salt) < 16:
            raise ValueError('File corrupted: cannot read salt')

        iv = f_in.read(16)
        if len(iv) < 16:
            raise ValueError('File corrupted: cannot read iv')

        mac = f_in.read(32)
        if len(mac) < 32:
            raise ValueError('File corrupted: cannot read MAC')

        enc_key = _derive_key(password, salt, dklen=32)
        mac_key = _derive_key(password, salt + b'auth', dklen=32)

        mac_ctx = hmac.new(mac_key, digestmod=hashlib.sha256)
        chunk_index = 0

        # Calculate data region size for progress display
        data_start = f_in.tell()
        total_data_size = file_size - data_start
        processed_size = 0

        # Dynamic chunk size limit
        remaining_size = total_data_size
        max_chunk = min(1024 * 1024, max(1024 * 64, remaining_size // 10 + 1024))

        # Stream decrypt and write
        with open(output_path, 'wb') as f_out:
            while True:
                # Read chunk length
                length_bytes = f_in.read(4)
                if not length_bytes:
                    break
                if len(length_bytes) < 4:
                    raise ValueError('File corrupted: incomplete chunk length')

                chunk_len = struct.unpack('>I', length_bytes)[0]

                if chunk_len == 0:
                    raise ValueError('File corrupted: chunk length is 0')
                if chunk_len > max_chunk:
                    raise ValueError(f'File corrupted: abnormal chunk length ({chunk_len} > {max_chunk})')

                # Read encrypted chunk
                encrypted_chunk = f_in.read(chunk_len)
                if len(encrypted_chunk) < chunk_len:
                    raise ValueError('File corrupted: incomplete chunk data')

                # Update HMAC
                mac_ctx.update(encrypted_chunk)

                # Decrypt
                keystream = _generate_keystream(enc_key, iv, chunk_index, len(encrypted_chunk))
                plaintext_chunk = bytes(b ^ k for b, k in zip(encrypted_chunk, keystream))

                # Stream write
                f_out.write(plaintext_chunk)
                chunk_index += 1

                # Update progress
                processed_size += 4 + chunk_len
                if progress_callback:
                    progress_callback(processed_size, total_data_size)

        # Verify MAC
        expected_mac = mac_ctx.digest()
        if not hmac.compare_digest(mac, expected_mac):
            if os.path.exists(output_path):
                os.remove(output_path)
            raise ValueError('Authentication failed: wrong key or file tampered')

# ==================== NalKey Feature (Simplified Obfuscation) ====================
def _simple_obfuscate(data):
    """Simple obfuscation: XOR + reverse"""
    salt = b'NalTool_TasKin_lZy@lOF04hqf?FM.waU^V[1ZW,e;TR5'
    result = bytearray()
    for i, byte in enumerate(data):
        result.append(byte ^ salt[i % len(salt)])
    result.reverse()
    return bytes(result)

def _simple_deobfuscate(data):
    """De-obfuscation"""
    reversed_data = data[::-1]
    salt = b'NalTool_TasKin_lZy@lOF04hqf?FM.waU^V[1ZW,e;TR5'
    result = bytearray()
    for i, byte in enumerate(reversed_data):
        result.append(byte ^ salt[i % len(salt)])
    return bytes(result)

def generate_nalkey(original_key, filename):
    """Generate nalkey file in NalTool directory (obfuscated version)"""
    script_dir = get_script_directory()
    nalkey_path = os.path.join(script_dir, f"{filename}.nalkey")
    
    key_bytes = original_key.encode('utf-8')
    obfuscated = _simple_obfuscate(key_bytes)
    encoded_key = b91encode(obfuscated)
    
    with open(nalkey_path, 'w', encoding='utf-8') as f:
        f.write(encoded_key)
    
    return nalkey_path

def load_nalkey(nalkey_path):
    """Load nalkey file, decode to get original key"""
    try:
        with open(nalkey_path, 'r', encoding='utf-8') as f:
            encoded_key = f.read().strip()
        obfuscated = b91decode(encoded_key)
        key_bytes = _simple_deobfuscate(obfuscated)
        original_key = key_bytes.decode('utf-8')
        return original_key
    except Exception as e:
        raise ValueError(f'Unable to read NalKey file: {str(e)}')

def find_nalkey_files():
    """Find all .nalkey files in NalTool directory"""
    script_dir = get_script_directory()
    nalkey_files = []
    try:
        for file in Path(script_dir).glob('*.nalkey'):
            nalkey_files.append(str(file))
    except Exception:
        pass
    return sorted(nalkey_files)

def get_password_with_nalkey(prompt='Enter key: ', allow_nalkey=True):
    """Get password, supports nalkey selection, displays * during input"""
    if not allow_nalkey:
        try:
            return get_password_with_asterisk(prompt)
        except Exception:
            return input(prompt)

    nalkey_files = find_nalkey_files()

    if nalkey_files:
        print(f'\nFound NalKey files (located in {get_script_directory()}):')
        print('[0] Enter key manually')
        for i, file in enumerate(nalkey_files, 1):
            print(f'[{i}] {os.path.basename(file)}')

        try:
            choice = input(f'\nPlease select (0-{len(nalkey_files)}): ').strip()
        except KeyboardInterrupt:
            print('\n')
            raise

        if choice.isdigit():
            idx = int(choice)
            if idx == 0:
                try:
                    return get_password_with_asterisk(prompt)
                except Exception:
                    return input(prompt)
            elif 1 <= idx <= len(nalkey_files):
                try:
                    password = load_nalkey(nalkey_files[idx-1])
                    print(f'Loaded key from {os.path.basename(nalkey_files[idx-1])}')
                    return password
                except Exception as e:
                    print(f'Failed to load NalKey: {e}')
                    print('Please enter key manually:')
                    try:
                        return get_password_with_asterisk(prompt)
                    except Exception:
                        return input(prompt)

    try:
        return get_password_with_asterisk(prompt)
    except Exception:
        return input(prompt)

# ==================== Command Line Interface ====================
def print_banner():
    print('NalTool - Encryption Tool - Made by TasKin - 3.2')
    print('TasKin Email: tnailkogns@hotmail.com')

def main():
    print_banner()

    while True:
        print()
        print('[1] Encrypt text')
        print('[2] Decrypt text')
        print('[3] Encrypt file')
        print('[4] Decrypt file')
        print('[5] Generate NalKey key file')
        print('[6] Exit')
        print()

        try:
            choice = input('Select operation (1-6): ').strip()
        except KeyboardInterrupt:
            print('\n')
            break
        except EOFError:
            break

        if choice == '1':
            try:
                text = input('Enter text to encrypt: ')
            except KeyboardInterrupt:
                print('\n')
                continue
            except EOFError:
                break

            if not text:
                print('Text cannot be empty')
                continue

            print('\nGetting encryption key...')
            try:
                password = get_password_with_nalkey('Enter encryption key: ', allow_nalkey=True)
            except KeyboardInterrupt:
                print('\n')
                continue

            if not password:
                print('Key cannot be empty')
                continue

            try:
                result = encrypt_text(text, password)
                print(f'\nEncryption result (length: {len(result)}):')
                print('===Encryption Result===')
                print(result)
                print('===Encryption Result===')
            except Exception as e:
                print(f'Encryption failed: {e}')

        elif choice == '2':
            try:
                encrypted = input('Enter ciphertext to decrypt: ')
            except KeyboardInterrupt:
                print('\n')
                continue
            except EOFError:
                break

            if not encrypted:
                print('Ciphertext cannot be empty')
                continue

            print('\nGetting decryption key...')
            try:
                password = get_password_with_nalkey('Enter decryption key: ', allow_nalkey=True)
            except KeyboardInterrupt:
                print('\n')
                continue

            if not password:
                print('Key cannot be empty')
                continue

            try:
                result = decrypt_text(encrypted, password)
                print(f'\nDecryption result (length: {len(result)}):')
                print('===Decryption Result===')
                print(result)
                print('===Decryption Result===')
            except Exception as e:
                print(f'Decryption failed: {e}')

        elif choice == '3':
            try:
                filepath = input('Enter file path: ').strip()
            except KeyboardInterrupt:
                print('\n')
                continue
            except EOFError:
                break

            if not os.path.exists(filepath):
                print('File not found')
                continue

            file_size = os.path.getsize(filepath)
            if file_size == 0:
                print('File is empty, cannot encrypt')
                continue

            print('\nGetting encryption key...')
            try:
                password = get_password_with_nalkey('Enter encryption key: ', allow_nalkey=True)
            except KeyboardInterrupt:
                print('\n')
                continue

            if not password:
                print('Key cannot be empty')
                continue

            try:
                output = filepath + '.nalfile'
                print(f'Encrypting file... (size: {file_size} bytes)')
                start_time = time.time()
                encrypt_file(filepath, output, password)
                elapsed = time.time() - start_time

                print(f'Encryption successful: {output}')
                print(f'Original size: {os.path.getsize(filepath)} bytes')
                print(f'Encrypted size: {os.path.getsize(output)} bytes')
                print(f'Time taken: {elapsed:.2f} seconds')
            except Exception as e:
                print(f'Encryption failed: {e}')
                if os.path.exists(output):
                    try:
                        os.remove(output)
                    except:
                        pass

        elif choice == '4':
            try:
                filepath = input('Enter file path: ').strip()
            except KeyboardInterrupt:
                print('\n')
                continue
            except EOFError:
                break

            if not os.path.exists(filepath):
                print('File not found')
                continue

            print('\nGetting decryption key...')
            try:
                password = get_password_with_nalkey('Enter decryption key: ', allow_nalkey=True)
            except KeyboardInterrupt:
                print('\n')
                continue

            if not password:
                print('Key cannot be empty')
                continue

            try:
                output = filepath[:-8] if filepath.endswith('.nalfile') else filepath + '.dec'
                # If output file already exists, add suffix
                if os.path.exists(output):
                    base, ext = os.path.splitext(output)
                    output = f"{base}_decrypted{ext}"
                
                print(f'Decrypting file... (size: {os.path.getsize(filepath)} bytes)')
                start_time = time.time()
                decrypt_file(filepath, output, password)
                elapsed = time.time() - start_time

                print(f'Decryption successful: {output}')
                print(f'Restored size: {os.path.getsize(output)} bytes')
                print(f'Time taken: {elapsed:.2f} seconds')

                try:
                    import subprocess
                    if sys.platform != 'win32':
                        result = subprocess.run(['file', '-b', output], capture_output=True, text=True)
                        if result.stdout:
                            file_type = result.stdout.strip()
                            if file_type and not file_type.startswith('data'):
                                print(f'File type: {file_type}')
                except:
                    pass
            except Exception as e:
                print(f'Decryption failed: {e}')
                if os.path.exists(output):
                    try:
                        os.remove(output)
                    except:
                        pass

        elif choice == '5':
            print('\nGenerating NalKey key file...')
            print(f'NalKey will be saved in: {get_script_directory()}')
            try:
                original_key = get_password_with_asterisk('Enter original key to encode: ')
            except KeyboardInterrupt:
                print('\n')
                continue

            if not original_key:
                print('Key cannot be empty')
                continue

            try:
                filename = input('Enter key filename (without extension): ').strip()
            except KeyboardInterrupt:
                print('\n')
                continue
            except EOFError:
                break

            if not filename:
                print('Filename cannot be empty')
                continue

            try:
                nalkey_path = generate_nalkey(original_key, filename)
                print(f'NalKey generated successfully: {nalkey_path}')
                print(f'Filename: {filename}.nalkey')
                print('Key stored with obfuscation, please keep this file safe')
            except Exception as e:
                print(f'Generation failed: {e}')

        elif choice == '6':
            print('Goodbye...')
            break

        else:
            print('Invalid option, please try again')

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print('\n\nProgram interrupted')
    except Exception as e:
        print(f'\nProgram error: {e}')
        import traceback
        traceback.print_exc()

# Made by TasKin
