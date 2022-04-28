"""
@author: cuny
@file: rsa_encryption.py
@time: 2022/4/21 21:32
@description: 
rsa加密算法，涉及密钥颁发和加解密
"""
# -*- coding: UTF-8 -*-
# ! /usr/bin/env python
import base64
import os
import rsa
from rsa import common
import socket
import ssl
from hyService.utils import Debug


# 使用 rsa库进行RSA签名和加解密
# 此类用于调试，
class RsaUtil(object):
    PUBLIC_KEY_PATH = './company_rsa_public_key.pem'  # 公钥
    PRIVATE_KEY_PATH = './company_rsa_private_key.pem'  # 私钥

    # 初始化key
    def __init__(self,
                 company_pub_file=PUBLIC_KEY_PATH,
                 company_pri_file=PRIVATE_KEY_PATH,
                 key_len: int = 1024,
                 if_write: bool = False):
        """
        类的初始化
        :param company_pub_file: 公钥保存路径
        :param company_pri_file: 私钥保存路径
        :param key_len: 密钥长度
        :param if_write: 是否保存密钥
        """
        self.key_len = key_len
        try:
            if not os.path.exists(company_pub_file) or not os.path.exists(company_pri_file):
                raise FileNotFoundError
            # 以匿名属性的方式生成公钥和私钥
            self.__company_public_key = rsa.PublicKey.load_pkcs1(open(company_pub_file, "rb").read())
            self.__company_private_key = rsa.PrivateKey.load_pkcs1(open(company_pri_file, "rb").read())
        except FileNotFoundError:
            (self.__company_public_key, self.__company_private_key) = rsa.newkeys(self.key_len)
            if if_write:
                pub = self.__company_public_key.save_pkcs1()
                pub_file = open(company_pub_file, 'wb')
                pub_file.write(pub)
                pub_file.close()
                pri = self.__company_private_key.save_pkcs1()
                pri_file = open(company_pri_file, 'wb')
                pri_file.write(pri)
                pri_file.close()

    def reset_key(self, if_write: bool = False):
        # 重制密钥
        (self.__company_public_key, self.__company_private_key) = rsa.newkeys(self.key_len)
        if if_write:
            pub = self.__company_public_key.save_pkcs1()
            pub_file = open(self.PUBLIC_KEY_PATH, 'wb')
            pub_file.write(pub)
            pub_file.close()
            pri = self.__company_private_key.save_pkcs1()
            pri_file = open(self.PRIVATE_KEY_PATH, 'wb')
            pri_file.write(pri)
            pri_file.close()

    @property
    def company_public_key(self):
        return self.__company_public_key

    @property
    def company_private_key(self):
        return self.__company_private_key

    @staticmethod
    def get_max_length(rsa_key, encrypt=True):
        """加密内容过长时 需要分段加密 换算每一段的长度.
            :param rsa_key: 钥匙.
            :param encrypt: 是否是加密.
        """
        blocksize = common.byte_size(rsa_key.n)
        reserve_size = 11  # 预留位为11
        if not encrypt:  # 解密时不需要考虑预留位
            reserve_size = 0
        maxlength = blocksize - reserve_size
        return maxlength

    # 加密 使用公钥加密
    def encrypt_by_public_key(self, message):
        """使用公钥加密.
            :param message: 需要加密的内容.
            加密之后需要对接过进行base64转码
        """
        encrypt_result = b''
        max_length = self.get_max_length(self.company_public_key)
        while message:
            input_data = message[:max_length]
            message = message[max_length:]
            out = rsa.encrypt(input_data, self.company_public_key)
            encrypt_result += out
        encrypt_result = base64.b64encode(encrypt_result)
        return encrypt_result

    # 解密，使用私钥解密
    def decrypt_by_private_key(self, message):
        """使用私钥解密.
            :param message: 需要加密的内容.
            解密之后的内容直接是字符串，不需要在进行转义
        """
        decrypt_result = b""
        max_length = self.get_max_length(self.company_private_key, False)
        decrypt_message = base64.b64decode(message)
        while decrypt_message:
            input_data = decrypt_message[:max_length]
            decrypt_message = decrypt_message[max_length:]
            out = rsa.decrypt(input_data, self.company_private_key)
            decrypt_result += out
        return decrypt_result

    # 签名 商户私钥 base64转码
    def sign_by_private_key(self, data: bytes):
        """私钥签名.
            :param data: 需要签名的内容.
            使用SHA-1 方法进行签名（也可以使用MD5）
            签名之后，需要转义后输出
        """
        signature = rsa.sign(data, priv_key=self.company_private_key, hash_method='SHA-1')
        return base64.b64encode(signature)

    # 验签 使用公钥验签
    def verify_by_public_key(self, message, signature):
        """公钥验签.
            :param message: 验签的内容.
            :param signature: 对验签内容签名的值（签名之后，会进行b64encode转码，所以验签前也需转码）.
        """
        signature = base64.b64decode(signature)
        return rsa.verify(message, signature, self.company_public_key)


# 此为服务端加密类，从安全性考虑，服务端的密钥不支持保存在本地
class XiaoHuanServer(Debug):
    def __init__(self, server_crt: str, pri_key: str, hostname: str = "cunyue.net", port: int = 5001):
        """初始化类，输入地址，创建socket链接
        :param server_crt: 证书路径
        :param pri_key: 私钥路径
        :param hostname: 域名地址
        :param port: 链接端口，默认为5001,5000端口用于nginx监听实现端口转发
        """
        self.hostname = hostname
        self.ip_port = port
        self.__ip = socket.gethostbyname(hostname)
        # 存储服务器所用证书和私钥路径
        self.server_crt = server_crt
        self.pri_key = pri_key
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    def build_listen(self):
        # 生成SSL上下文
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        # 加载服务器所用证书和私钥
        context.load_cert_chain(self.server_crt, self.pri_key)

        # 监听端口
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0) as sock:
            sock.bind(('127.0.0.1', self.ip_port))
            sock.listen(5)
            # 将socket打包成SSL socket
            with context.wrap_socket(sock, server_side=True) as ssock:
                while True:
                    # 接收客户端连接
                    client_socket, addr = ssock.accept()
                    # 接收客户端信息
                    msg = client_socket.recv(1024).decode("utf-8")
                    print(f"receive msg from client {addr}：{msg}")
                    # 向客户端发送信息
                    msg = f"yes , you have client_socketect with server.\r\n".encode("utf-8")
                    client_socket.send(msg)
                    client_socket.close()


if __name__ == "__main__":
    message_ = '你好'
    print("明文内容：>>> ")
    print(message_)
    message_ = bytes(message_, encoding="utf8")
    rsaUtil = RsaUtil()
    encrypy_result_ = rsaUtil.encrypt_by_public_key(message_)
    print("加密结果：>>> ")
    print(encrypy_result_)
    decrypt_result_ = rsaUtil.decrypt_by_private_key(encrypy_result_)
    print("解密结果：>>> ")
    print(str(decrypt_result_, encoding="utf-8"))
    sign_ = rsaUtil.sign_by_private_key(message_)
    print("签名结果：>>> ")
    print(sign_)
    print("验签结果：>>> ")
    print(rsaUtil.verify_by_public_key(message_, sign_))
    xh = XiaoHuanServer(server_crt="./openssl_cert/server.crt", pri_key="./openssl_cert/ca.key")
    xh.build_listen()
