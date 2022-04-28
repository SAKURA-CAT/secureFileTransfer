"""
@author: cuny
@file: userAuth.py
@time: 2022/4/27 11:42
@description: 
用户认证系统，目前是通过简单的对称密钥认证方式认证客户端，然后通过rsa加密aes交换加密密钥，最后通过aes继续通讯。
首先是一个基本类Auth，然后通过基本类衍生出客户端类HYClient和服务端类XiaoHuanSever。
"""
import socket
from Crypto.Cipher import AES
from hyService.utils import Debug
import base64
import os
import hmac


class Auth(object):
    """
    认证基本类，将基于socket进行通讯，并且封装了一些认证函数，支持Debug，默认不开启
    这一部分的整个通讯采用明文通讯，仿照TLS协议。主要的目的是防止恶意篡改。这里和openssl主要的区别就是少了认证签名。
    没有用openssl的原因是目前实力不够，没有特别能够理解openssl的整个作用。
    """
    __secret_key: bytes = b'cuny'

    def __init__(self, digestmod: str = "MD5"):
        """
        初始化
        :param digestmod: 认证方式
        """
        self.digestmod = digestmod
        self.__random_code: bytes = b''

    @staticmethod
    def randomCodeSend(connection):
        """
        这是一个随机数生成/发送方法，在建立连接以后生成一个随机码发送给连接的另一端
        :param connection: 建立的连接对象
        """
        message = os.urandom(32)
        connection.send(message)
        return message

    @property
    def random_code(self):
        if len(self.__random_code) == 0:
            raise ValueError("random_code为空,不可读取!")
        return self.__random_code

    @random_code.setter
    def random_code(self, value: bytes):
        """
        random_code支持部分写，即输入value以后会将value和原本的random_code的整形形式进行拼接
        Args:
            value: 待计算平均值的数据
        """
        if not isinstance(value, bytes):
            raise TypeError("random_code必须为byte格式!")
        if self.__random_code == b'':
            self.__random_code = value
        else:
            tmp = (int.from_bytes(self.__random_code, byteorder='big') + int.from_bytes(value, byteorder='big')) // 2
            self.__random_code = tmp.to_bytes(32, byteorder="big")

    @property
    def secret_key(self):
        return self.__secret_key

    def authenticate(self, connection, random_code: bytes = None):
        """
        这是一个认证方法，输入socket连接和随机码random_code，然后通过digestmod方法进行解析，最终返回认证结果
        Args:
            connection: socket连接
            random_code: 随机码，这里的随机码推荐仿照TLS协议方式，由三次握手携带的随机码拼接而成,推荐采用内置rand_code方式输入

        Returns:
            如果认证失败，则返回None
        """
        if random_code is None:
            random_code = self.random_code
        hash_code = hmac.new(bytes(self.__secret_key), random_code, digestmod=self.digestmod)
        digest = hash_code.digest()
        # 从socket连接返回认证结果
        response = connection.recv(len(digest))
        # 对digest和response进行比较，如果相同则说明认证成功
        return hmac.compare_digest(digest, response)

    # 加密方法
    def encrypt_oracle(self, text):
        def add_to_16(value):
            while len(value) % 16 != 0:
                value += '\0'
            return str.encode(value)  # 返回bytes
        # 秘钥
        key = self.random_code
        # 初始化加密器
        aes = AES.new(key, AES.MODE_ECB)
        # 先进行aes加密
        encrypt_aes = aes.encrypt(add_to_16(text))
        # 用base64转成字符串形式
        encrypted_text = str(base64.encodebytes(encrypt_aes), encoding='utf-8')  # 执行加密并转码返回bytes
        return encrypted_text

    # 解密方法
    def decrypt_oracle(self, text):
        # 秘钥
        key = self.random_code
        # 初始化加密器
        aes = AES.new(key, AES.MODE_ECB)
        # 优先逆向解密base64成bytes
        base64_decrypted = base64.decodebytes(text.encode(encoding='utf-8'))
        # 执行解密密并转码返回str
        decrypted_text = str(aes.decrypt(base64_decrypted), encoding='utf-8').replace('\0', '')
        return decrypted_text


class XiaoHuanServer(Auth):
    """

    """
    def __init__(self, host: str = '', port: int = 5001, max_con: int = 5, debug: bool = False, *args, **kwargs):
        """
        初始化方法，定义socket监听的地址和端口
        Args:
            host: 地址，默认为127.0.0.1
            port: 端口，默认为5000
            debug: 是否开启调试
            *args: 其他属性
            **kwargs: 其他属性
        """
        super().__init__(*args, **kwargs)
        self.db = Debug()
        self.db.debug = debug
        self.host = host
        self.port = port
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.bind((host, port))
        self.server_socket.listen(max_con)

    def enter_dialogue(self, connection):
        """
        进入会话以后的函数
        Args:
            connection:

        Returns:

        """
        self.db.debug_print("INFO: authentication succeed,enter dialogue.", font_color="green")
        connection.send(b'success')
        while not connection.close():
            text = connection.recv(1024)
            # 客户端发送的数据为空的无效数据
            if len(text.strip()) == 0:
                pass
            else:
                print("收到客户端发送的数据为：{}".format(text.decode()))
                print("解密后的数据为：{}".format(self.decrypt_oracle(text.decode())))
                content = input("请输入发送给客户端的信息：")
                # 返回服务端发送的信息
                connection.send(content.encode())

    def run_server(self):
        self.db.debug_print("waiting for connection...", font_color="yellow")
        while True:
            # 阻塞连接
            c, a = self.server_socket.accept()
            self.db.debug_print(f"INFO: received message from {a}, start shaking hands..", font_color="green")
            # 第一次握手，从c中获得第一个随机数，随机数长度为32位
            self.random_code = c.recv(32)
            self.db.debug_print(f"INFO: first handshake, get random_code...", font_color="blue")
            # 接收到连接以后，回传一个random_code，作为第二个随机数
            random_code = self.randomCodeSend(c)
            self.random_code = random_code
            self.db.debug_print(f"INFO: second handshake, get random_code...", font_color="blue")
            # 第三次握手，接收第三个随机数
            random_code = c.recv(32)
            self.random_code = random_code
            self.db.debug_print(f"INFO: third handshake, get random_code...", font_color="blue")
            # 随机数获取完毕，开始验证
            if self.authenticate(c) is None:
                self.db.debug_print(f"WARN: authentication failed!", font_color="red")
                # 可以向socket发送认证失败的字段
                c.close()  # 关闭连接
            else:
                # 进入对话,后续在验证环节或许要把密钥交换做好，现在先不管
                self.enter_dialogue(connection=c)


class HYClient(Auth):
    def __init__(self, hostname: str = 'cunyue.net', port: int = 5000, debug: bool = False, *args, **kwargs):
        """
        初始化方法，定义socket监听的地址和端口
        Args:
            host: 路由地址，默认为cunyue
            port: 端口，默认为5000
            debug: 是否开启调试
            *args: 其他属性
            **kwargs: 其他属性
        """
        super().__init__(*args, **kwargs)
        self.db = Debug()
        self.db.debug = debug
        self.host = socket.gethostbyname(hostname)
        self.db.debug_print(f"INFO: {hostname} resolves to {self.host}", font_color="yellow")
        self.port = port
        self.client_socket = socket.socket()

    def enter_dialogue(self, connection):
        self.db.debug_print("INFO: enter dialogue.", font_color="green")
        while True:
            send_data = self.encrypt_oracle(input("客户端要发送的信息："))
            # 进行数据加密，采用最简单的形式
            # socket传递的都是bytes类型的数据,需要转换一下
            connection.send(send_data.encode())
            # 接收数据，最大字节数1024,对返回的二进制数据进行解码
            text = connection.recv(1024).decode()
            print("服务端发送的数据：{}".format(text))
            print("------------------------------")

    def connect_server(self):
        # 开始握手
        self.db.debug_print(f"INFO: attempt to handshake with client...", font_color="green")
        self.client_socket.connect((self.host, self.port))
        # 首先向服务端发送第一个随机数
        self.random_code = self.randomCodeSend(self.client_socket)
        self.db.debug_print(f"INFO: first handshake, send random_code...", font_color="blue")
        # 接收服务器发送的随机数
        self.random_code = self.client_socket.recv(32)
        self.db.debug_print(f"INFO: second handshake, get random_code...", font_color="blue")
        # 第三次握手
        self.random_code = self.randomCodeSend(self.client_socket)
        self.db.debug_print(f"INFO: third handshake, send random_code...", font_color="blue")
        # 根据随机数和密钥开始认证
        hash_code = hmac.new(self.secret_key, self.random_code, digestmod="MD5")
        digest = hash_code.digest()
        self.client_socket.send(digest)  # 发送认证结果，服务端确认
        # 获取求证结果
        if self.client_socket.recv(7) == b'success':
            self.db.debug_print(f"INFO: authenticate success!", font_color="green")
            self.enter_dialogue(self.client_socket)
        else:
            self.db.debug_print(f"WARN: authenticate failed!", font_color="red")


if __name__ == "__main__":
    # a = os.urandom(32)
    # b = os.urandom(32)
    # c = (int.from_bytes(a, byteorder='big') + int.from_bytes(b, byteorder='big')) // 2
    # d = c.to_bytes(32, byteorder="big")
    # e = int.from_bytes(d, byteorder='big')
    xhs = XiaoHuanServer(debug=True)
    a = xhs.random_code
    # xhs.authenticate(None, random_code=os.urandom(32))
