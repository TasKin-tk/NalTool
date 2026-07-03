#NalTool - TasKin Made - 3.2

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

# ==================== 版本信息 ====================
VERSION = "3.2"
AUTHOR = "TasKin"
EMAIL = "tnailkogns@hotmail.com"
MAGIC_HEADER = b'NALT'  # 文件头魔数，用于识别
HEADER_VERSION = 1      # 文件格式版本

# ==================== 平台检测 ====================
IS_WINDOWS = sys.platform == 'win32'
IS_UNIX = sys.platform in ('linux', 'darwin', 'cygwin', 'freebsd')

# ==================== 跨平台密码输入 ====================
def get_password_with_asterisk(prompt='请输入密钥: '):
    """密码输入时显示 * 号，跨平台支持"""
    if IS_WINDOWS:
        import msvcrt
        print(prompt, end='', flush=True)
        password = []
        while True:
            ch = msvcrt.getch()
            if ch in (b'\r', b'\n'):
                print()
                break
            elif ch == b'\x08':  # 退格键
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
        # Unix/Linux/macOS 使用 termios
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
                    elif ch == '\x7f' or ch == '\x08':  # 退格键
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

# ==================== 获取脚本所在目录 ====================
def get_script_directory():
    """获取NalTool脚本所在的目录"""
    return os.path.dirname(os.path.abspath(__file__))

# ==================== Base91 编解码 ====================
B91_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!#$%&()*+,./:;<=>?@[]^_`{|}~"'

def b91encode(data):
    """Base91编码"""
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
    """Base91解码"""
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

# ==================== 加密核心 ====================
def _derive_key(password, salt, iterations=600000, dklen=32):
    """PBKDF2-HMAC-SHA256 密钥派生"""
    return hashlib.pbkdf2_hmac(
        'sha256',
        password.encode('utf-8'),
        salt,
        iterations,
        dklen
    )

def _generate_keystream(key, iv, counter, length):
    """使用HMAC-SHA256生成CTR模式的密钥流"""
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
    """加密文本 → Base91字符串（带HMAC认证）"""
    if not text:
        raise ValueError('文本不能为空')
    if not password:
        raise ValueError('密钥不能为空')
    
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
    """从Base91字符串解密文本（带HMAC验证）"""
    if not encrypted:
        raise ValueError('密文不能为空')
    if not password:
        raise ValueError('密钥不能为空')
    
    try:
        data = b91decode(encrypted)
        if len(data) < 64:  # salt(16) + iv(16) + mac(32)
            raise ValueError('数据损坏：长度不足64字节')
        
        salt = data[:16]
        iv = data[16:32]
        mac = data[32:64]
        ciphertext = data[64:]
        
        if not ciphertext:
            raise ValueError('数据损坏：密文为空')
        
        enc_key = _derive_key(password, salt, dklen=32)
        mac_key = _derive_key(password, salt + b'auth', dklen=32)
        
        # 验证HMAC
        expected_mac = hmac.new(mac_key, ciphertext, hashlib.sha256).digest()
        if not hmac.compare_digest(mac, expected_mac):
            raise ValueError('认证失败：密钥错误或数据被篡改')
        
        plaintext = bytearray()
        for i in range(0, len(ciphertext), 16):
            block = ciphertext[i:i+16]
            keystream = _generate_keystream(enc_key, iv, i // 16, len(block))
            plaintext.extend(b ^ k for b, k in zip(block, keystream))
        
        return plaintext.decode('utf-8')
        
    except UnicodeDecodeError:
        raise ValueError('解密失败：密钥错误或数据损坏')
    except ValueError as e:
        if '认证失败' in str(e):
            raise
        raise ValueError(f'解密失败: {str(e)}')
    except Exception as e:
        raise ValueError(f'解密失败: {str(e)}')

# ==================== 文件处理（分块加密，优化版） ====================
def encrypt_file(input_path, output_path, password):
    """
    加密文件（分块处理，支持大文件）
    格式：[MAGIC(4)][VERSION(1)][salt(16)][iv(16)][mac(32)][encrypted_chunks...]
    使用增量HMAC，内存友好
    """
    if not os.path.exists(input_path):
        raise FileNotFoundError(f'文件不存在: {input_path}')
    if not password:
        raise ValueError('密钥不能为空')
    
    file_size = os.path.getsize(input_path)
    if file_size == 0:
        raise ValueError('文件为空，无法加密')
    
    salt = os.urandom(16)
    iv = os.urandom(16)
    
    enc_key = _derive_key(password, salt, dklen=32)
    mac_key = _derive_key(password, salt + b'auth', dklen=32)
    
    chunk_size = 64 * 1024  # 64KB
    
    with open(input_path, 'rb') as f_in, open(output_path, 'wb') as f_out:
        # 写入文件头：魔数 + 版本号
        f_out.write(MAGIC_HEADER)
        f_out.write(struct.pack('>B', HEADER_VERSION))
        
        # 写入salt和iv
        f_out.write(salt)
        f_out.write(iv)
        
        # 预留MAC位置
        mac_pos = f_out.tell()
        f_out.write(b'\x00' * 32)
        
        # 使用增量HMAC，不需要保存所有密文
        mac_ctx = hmac.new(mac_key, digestmod=hashlib.sha256)
        chunk_index = 0
        
        while True:
            chunk = f_in.read(chunk_size)
            if not chunk:
                break
            
            keystream = _generate_keystream(enc_key, iv, chunk_index, len(chunk))
            encrypted_chunk = bytes(b ^ k for b, k in zip(chunk, keystream))
            
            # 写入块长度和加密数据
            f_out.write(struct.pack('>I', len(encrypted_chunk)))
            f_out.write(encrypted_chunk)
            
            # 更新HMAC
            mac_ctx.update(encrypted_chunk)
            chunk_index += 1
        
        # 计算并写入MAC
        mac = mac_ctx.digest()
        f_out.seek(mac_pos)
        f_out.write(mac)
        
        # 确保文件指针在末尾
        f_out.seek(0, os.SEEK_END)

def decrypt_file(input_path, output_path, password, progress_callback=None):
    """
    解密文件（流式写入，内存友好）

    Args:
        input_path: 加密文件路径
        output_path: 输出文件路径
        password: 解密密钥
        progress_callback: 可选进度回调函数 (current, total)
    """
    if not os.path.exists(input_path):
        raise FileNotFoundError(f'文件不存在: {input_path}')
    if not password:
        raise ValueError('密钥不能为空')

    file_size = os.path.getsize(input_path)
    if file_size < 4 + 1 + 16 + 16 + 32:
        raise ValueError('文件损坏：文件头不完整')

    with open(input_path, 'rb') as f_in:
        # 读取并验证文件头
        magic = f_in.read(4)
        if magic != MAGIC_HEADER:
            raise ValueError('文件损坏：无效的文件格式')

        version_bytes = f_in.read(1)
        if not version_bytes:
            raise ValueError('文件损坏：无法读取版本号')
        version = struct.unpack('>B', version_bytes)[0]
        if version != HEADER_VERSION:
            raise ValueError(f'不支持的版本: {version}')

        salt = f_in.read(16)
        if len(salt) < 16:
            raise ValueError('文件损坏：无法读取salt')

        iv = f_in.read(16)
        if len(iv) < 16:
            raise ValueError('文件损坏：无法读取iv')

        mac = f_in.read(32)
        if len(mac) < 32:
            raise ValueError('文件损坏：无法读取MAC')

        enc_key = _derive_key(password, salt, dklen=32)
        mac_key = _derive_key(password, salt + b'auth', dklen=32)

        mac_ctx = hmac.new(mac_key, digestmod=hashlib.sha256)
        chunk_index = 0

        # 计算数据区域大小（用于进度显示）
        data_start = f_in.tell()
        total_data_size = file_size - data_start
        processed_size = 0

        # 动态块大小限制
        remaining_size = total_data_size
        max_chunk = min(1024 * 1024, max(1024 * 64, remaining_size // 10 + 1024))

        # 流式解密并写入
        with open(output_path, 'wb') as f_out:
            while True:
                # 读取块长度
                length_bytes = f_in.read(4)
                if not length_bytes:
                    break
                if len(length_bytes) < 4:
                    raise ValueError('文件损坏：块长度不完整')

                chunk_len = struct.unpack('>I', length_bytes)[0]

                if chunk_len == 0:
                    raise ValueError('文件损坏：块长度为0')
                if chunk_len > max_chunk:
                    raise ValueError(f'文件损坏：块长度异常 ({chunk_len} > {max_chunk})')

                # 读取加密块
                encrypted_chunk = f_in.read(chunk_len)
                if len(encrypted_chunk) < chunk_len:
                    raise ValueError('文件损坏：块数据不完整')

                # 更新HMAC
                mac_ctx.update(encrypted_chunk)

                # 解密
                keystream = _generate_keystream(enc_key, iv, chunk_index, len(encrypted_chunk))
                plaintext_chunk = bytes(b ^ k for b, k in zip(encrypted_chunk, keystream))

                # 流式写入
                f_out.write(plaintext_chunk)
                chunk_index += 1

                # 更新进度
                processed_size += 4 + chunk_len
                if progress_callback:
                    progress_callback(processed_size, total_data_size)

        # 验证MAC
        expected_mac = mac_ctx.digest()
        if not hmac.compare_digest(mac, expected_mac):
            if os.path.exists(output_path):
                os.remove(output_path)
            raise ValueError('认证失败：密钥错误或文件被篡改')

# ==================== NalKey 功能（简化混淆版） ====================
def _simple_obfuscate(data):
    """简单混淆：异或 + 反转"""
    salt = b'NalTool_TasKin_lZy@lOF04hqf?FM.waU^V[1ZW,e;TR5'
    result = bytearray()
    for i, byte in enumerate(data):
        result.append(byte ^ salt[i % len(salt)])
    result.reverse()
    return bytes(result)

def _simple_deobfuscate(data):
    """反混淆"""
    reversed_data = data[::-1]
    salt = b'NalTool_TasKin_lZy@lOF04hqf?FM.waU^V[1ZW,e;TR5'
    result = bytearray()
    for i, byte in enumerate(reversed_data):
        result.append(byte ^ salt[i % len(salt)])
    return bytes(result)

def generate_nalkey(original_key, filename):
    """在NalTool同目录下生成nalkey文件（混淆版）"""
    script_dir = get_script_directory()
    nalkey_path = os.path.join(script_dir, f"{filename}.nalkey")
    
    key_bytes = original_key.encode('utf-8')
    obfuscated = _simple_obfuscate(key_bytes)
    encoded_key = b91encode(obfuscated)
    
    with open(nalkey_path, 'w', encoding='utf-8') as f:
        f.write(encoded_key)
    
    return nalkey_path

def load_nalkey(nalkey_path):
    """加载nalkey文件，解码得到原始密钥"""
    try:
        with open(nalkey_path, 'r', encoding='utf-8') as f:
            encoded_key = f.read().strip()
        obfuscated = b91decode(encoded_key)
        key_bytes = _simple_deobfuscate(obfuscated)
        original_key = key_bytes.decode('utf-8')
        return original_key
    except Exception as e:
        raise ValueError(f'无法读取NalKey文件: {str(e)}')

def find_nalkey_files():
    """在NalTool同目录下查找所有.nalkey文件"""
    script_dir = get_script_directory()
    nalkey_files = []
    try:
        for file in Path(script_dir).glob('*.nalkey'):
            nalkey_files.append(str(file))
    except Exception:
        pass
    return sorted(nalkey_files)

def get_password_with_nalkey(prompt='请输入密钥: ', allow_nalkey=True):
    """获取密码，支持nalkey选择，输入时显示*号"""
    if not allow_nalkey:
        try:
            return get_password_with_asterisk(prompt)
        except Exception:
            return input(prompt)

    nalkey_files = find_nalkey_files()

    if nalkey_files:
        print(f'\n发现以下NalKey文件 (位于 {get_script_directory()}):')
        print('[0] 手动输入密钥')
        for i, file in enumerate(nalkey_files, 1):
            print(f'[{i}] {os.path.basename(file)}')

        try:
            choice = input(f'\n请选择 (0-{len(nalkey_files)}): ').strip()
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
                    print(f'已从 {os.path.basename(nalkey_files[idx-1])} 加载密钥')
                    return password
                except Exception as e:
                    print(f'加载NalKey失败: {e}')
                    print('请手动输入密钥:')
                    try:
                        return get_password_with_asterisk(prompt)
                    except Exception:
                        return input(prompt)

    try:
        return get_password_with_asterisk(prompt)
    except Exception:
        return input(prompt)

# ==================== 命令行界面 ====================
def print_banner():
    print('NalTool - 加解密工具 - TasKin 制作 - 3.2')
    print('TasKin 邮箱：tnailkogns@hotmail.com')

def main():
    print_banner()

    while True:
        print()
        print('[1] 加密文本')
        print('[2] 解密文本')
        print('[3] 加密文件')
        print('[4] 解密文件')
        print('[5] 生成NalKey密钥文件')
        print('[6] 退出')
        print()

        try:
            choice = input('请选择操作 (1-6): ').strip()
        except KeyboardInterrupt:
            print('\n')
            break
        except EOFError:
            break

        if choice == '1':
            try:
                text = input('请输入要加密的文本: ')
            except KeyboardInterrupt:
                print('\n')
                continue
            except EOFError:
                break

            if not text:
                print('文本不能为空')
                continue

            print('\n获取加密密钥...')
            try:
                password = get_password_with_nalkey('请输入加密密钥: ', allow_nalkey=True)
            except KeyboardInterrupt:
                print('\n')
                continue

            if not password:
                print('密钥不能为空')
                continue

            try:
                result = encrypt_text(text, password)
                print(f'\n加密结果 (长度: {len(result)}):')
                print('===加密结果===')
                print(result)
                print('===加密结果===')
            except Exception as e:
                print(f'加密失败: {e}')

        elif choice == '2':
            try:
                encrypted = input('请输入要解密的密文: ')
            except KeyboardInterrupt:
                print('\n')
                continue
            except EOFError:
                break

            if not encrypted:
                print('密文不能为空')
                continue

            print('\n获取解密密钥...')
            try:
                password = get_password_with_nalkey('请输入解密密钥: ', allow_nalkey=True)
            except KeyboardInterrupt:
                print('\n')
                continue

            if not password:
                print('密钥不能为空')
                continue

            try:
                result = decrypt_text(encrypted, password)
                print(f'\n解密结果 (长度: {len(result)}):')
                print('===解密结果===')
                print(result)
                print('===解密结果===')
            except Exception as e:
                print(f'解密失败: {e}')

        elif choice == '3':
            try:
                filepath = input('请输入文件路径: ').strip()
            except KeyboardInterrupt:
                print('\n')
                continue
            except EOFError:
                break

            if not os.path.exists(filepath):
                print('文件不存在')
                continue

            file_size = os.path.getsize(filepath)
            if file_size == 0:
                print('文件为空，无法加密')
                continue

            print('\n获取加密密钥...')
            try:
                password = get_password_with_nalkey('请输入加密密钥: ', allow_nalkey=True)
            except KeyboardInterrupt:
                print('\n')
                continue

            if not password:
                print('密钥不能为空')
                continue

            try:
                output = filepath + '.nalfile'
                print(f'正在加密文件... (大小: {file_size} 字节)')
                start_time = time.time()
                encrypt_file(filepath, output, password)
                elapsed = time.time() - start_time

                print(f'加密成功: {output}')
                print(f'原始大小: {os.path.getsize(filepath)} 字节')
                print(f'加密后大小: {os.path.getsize(output)} 字节')
                print(f'耗时: {elapsed:.2f} 秒')
            except Exception as e:
                print(f'加密失败: {e}')
                if os.path.exists(output):
                    try:
                        os.remove(output)
                    except:
                        pass

        elif choice == '4':
            try:
                filepath = input('请输入文件路径: ').strip()
            except KeyboardInterrupt:
                print('\n')
                continue
            except EOFError:
                break

            if not os.path.exists(filepath):
                print('文件不存在')
                continue

            print('\n获取解密密钥...')
            try:
                password = get_password_with_nalkey('请输入解密密钥: ', allow_nalkey=True)
            except KeyboardInterrupt:
                print('\n')
                continue

            if not password:
                print('密钥不能为空')
                continue

            try:
                output = filepath[:-8] if filepath.endswith('.nalfile') else filepath + '.dec'
                # 如果输出文件已存在，添加后缀
                if os.path.exists(output):
                    base, ext = os.path.splitext(output)
                    output = f"{base}_decrypted{ext}"
                
                print(f'正在解密文件... (大小: {os.path.getsize(filepath)} 字节)')
                start_time = time.time()
                decrypt_file(filepath, output, password)
                elapsed = time.time() - start_time

                print(f'解密成功: {output}')
                print(f'恢复大小: {os.path.getsize(output)} 字节')
                print(f'耗时: {elapsed:.2f} 秒')

                try:
                    import subprocess
                    if sys.platform != 'win32':
                        result = subprocess.run(['file', '-b', output], capture_output=True, text=True)
                        if result.stdout:
                            file_type = result.stdout.strip()
                            if file_type and not file_type.startswith('data'):
                                print(f'文件类型: {file_type}')
                except:
                    pass
            except Exception as e:
                print(f'解密失败: {e}')
                if os.path.exists(output):
                    try:
                        os.remove(output)
                    except:
                        pass

        elif choice == '5':
            print('\n生成NalKey密钥文件...')
            print(f'NalKey将保存在: {get_script_directory()}')
            try:
                original_key = get_password_with_asterisk('请输入要编码的原始密钥: ')
            except KeyboardInterrupt:
                print('\n')
                continue

            if not original_key:
                print('密钥不能为空')
                continue

            try:
                filename = input('请输入密钥文件名（不含扩展名）: ').strip()
            except KeyboardInterrupt:
                print('\n')
                continue
            except EOFError:
                break

            if not filename:
                print('文件名不能为空')
                continue

            try:
                nalkey_path = generate_nalkey(original_key, filename)
                print(f'NalKey生成成功: {nalkey_path}')
                print(f'文件名: {filename}.nalkey')
                print('密钥已混淆存储，请妥善保管此文件')
            except Exception as e:
                print(f'生成失败: {e}')

        elif choice == '6':
            print('再见...')
            break

        else:
            print('无效选项，请重新选择')

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print('\n\n程序已中断')
    except Exception as e:
        print(f'\n程序异常: {e}')
        import traceback
        traceback.print_exc()

# TasKin Made
