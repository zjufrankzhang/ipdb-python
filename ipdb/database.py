# -*- coding: utf-8 -*-
"""
    :copyright: ©2018 by IPIP.net
"""

import ipaddress
import json
import sys
import csv, codecs

from .util import bytes2long
from .exceptions import NoSupportIPv4Error, NoSupportIPv6Error, NoSupportLanguageError, DatabaseError, IPNotFound


class MetaData(object):
    def __init__(self, **kwargs):
        self.fields = kwargs['fields']
        self.node_count = kwargs['node_count']
        self.total_size = kwargs['total_size']
        self.build = kwargs['build']
        self.languages = kwargs['languages']
        self.ip_version = kwargs['ip_version']

class TreeNode:
    _data = b""
    address = 0
    depth = 0
    byte_addr = bytearray()

    def __init__(self, data):
        self._data = data

    def _read_node(self, node, idx):
        off = idx * 4 + node * 8
        return bytes2long(self._data[off], self._data[off + 1], self._data[off + 2], self._data[off + 3])

    def left_child(self):
        return self._read_node(self.address, 0)
    
    def right_child(self):
        return self._read_node(self.address, 1)

    def set_value(self, idx, value):
        if(value):
            tmp0 = idx >> 3         #确定取第0/1/2/3个byte
            tmp1 = idx % 8          #确定在当前byte的第几位
            tmp2 = bytearray([128])
            tmp3 = tmp2[0] >> tmp1     #对byte位移得到目标翻转mask
            self.byte_addr[tmp0]  = self.byte_addr[tmp0] | tmp3
        return 0

class Dumper:
    _meta = {}
    data = b""

    #_off = 0

    _v4offset = 0
    _v6offsetCache = {}

    def __init__(self, name):
        self._v4offset = 0
        self._v6offsetCache = {}

        file = open(name, "rb")
        self.data = file.read()
        self._file_size = len(self.data)
        file.close()
        meta_length = bytes2long(self.data[0], self.data[1], self.data[2], self.data[3])
        if sys.version_info < (3,0):
            meta = json.loads(str(self.data[4:meta_length + 4]))
        else:
            meta = json.loads(str(self.data[4:meta_length + 4], 'utf-8'))

        self._meta = MetaData(**meta)
        if len(self._meta.languages) == 0 or len(self._meta.fields) == 0:
            raise DatabaseError("database meta error")
        if self._file_size != (4 + meta_length + self._meta.total_size):
            raise DatabaseError("database size error")

        self.data = self.data[4+meta_length:]


    def _resolve(self, node):
        resolved = node - self._meta.node_count + self._meta.node_count * 8
        size = bytes2long(0, 0, self.data[resolved], self.data[resolved + 1])
        if (resolved+2+size) > len(self.data):
            raise DatabaseError("database is error")
        return self.data[resolved+2:resolved+2+size]

    #下面这个函数是输出数据的部分，如果需要调整输出的数据类型，修改这里即可
    def print_cur_info(self, pnode):
        bs = self._resolve(pnode.address)
        if bs is None:
            return None

        tmp = bs.decode("utf-8").split("\t")
        #根据off判断语言版本的字段，目前dump所有语言，暂时去掉
        #end = self._off + len(self._meta.fields)
        #if len(tmp) < end:
        #    raise DatabaseError("database is error")
        ipstr = '.'.join(f'{c}' for c in pnode.byte_addr)      
        #上面这个是网上找的转换方法，还没仔细研究，但确实有用，把bin的IP转成数字表示的。版本要求3.6+
        #ipnet = ipaddress.ip_network(ipstr +'/'+ str(pnode.depth))
        #print((ipnet.compressed, tmp))
        if(self._csv_writer):
            self._csv_writer.writerow([ipstr +'/'+ str(pnode.depth), pnode.address, tmp[0], tmp[1], tmp[2]])
            #这里图省事没搞tmp的计数，直接按照免费版弄tmp[2]了
        return 0

    def _read_node(self, node, idx):
        off = idx * 4 + node * 8
        return bytes2long(self.data[off], self.data[off + 1], self.data[off + 2], self.data[off + 3])

    def dump_all(self, file_name):
        #find里面的off变量初始化，暂时去掉，dump所有语言版本
        #off = self._meta.languages.get(language)
        #if off is None:
        #    raise NoSupportLanguageError(language + " is not support")
        #self._off = off

        #初始化输出的文件
        csv_file = codecs.open(file_name,"w", 'utf_8_sig')
        self._csv_writer = csv.writer(csv_file)

        #从find_node里面取的初始化代码，取消了ipv6相关判断
        node = 0
        if self._v4offset == 0:
            i = 0
            while i < 96:
                if i >= 80:
                    node = self._read_node(node, 1)
                else:
                    node = self._read_node(node, 0)
                i += 1
            self._v4offset = node
        else:
            node = self._v4offset
        #此处node即为ipv4字典树的根节点byte数组索引地址

        stack = []
        pnode = TreeNode(self.data)
        pnode.address = node
        pnode.depth = 0
        pnode.byte_addr = bytearray([0,0,0,0])

        #深度优先搜索遍历二叉树的算法，使用循环式写法，显式引入堆栈
        #本遍历方法的前提条件，左右子树一定同时具备，此时节点只有中间和叶子两种节点类型
        #此循环条件无法读取最后一个叶子节点，需在循环结束后单独读取
        #（如只有一个根节点的情形，就根本不会进入循环）
        while pnode.address <= self._meta.node_count or len(stack):     #//当前节点不是叶子，或栈非空条件下循环 （当前节点是叶子且栈空时停止）
            if pnode.depth > 32:     #防止异常逻辑溢出
                break
            if pnode.address <= self._meta.node_count: #当前节点是中间节点，需要取左子树
                stack.append(pnode)
                new_node = TreeNode(self.data)
                new_node.address = pnode.left_child()
                new_node.depth = pnode.depth + 1
                new_node.byte_addr = pnode.byte_addr.copy()
                new_node.set_value(new_node.depth-1, 0)
                pnode = new_node
            else:        #当前节点是叶子节点，先读取本节点信息并保存，然后从堆栈里取出最上面元素
                self.print_cur_info(pnode)
                node = stack.pop()
                new_node = TreeNode(self.data)
                new_node.address = node.right_child()
                new_node.depth = node.depth + 1
                new_node.byte_addr = node.byte_addr.copy()
                new_node.set_value(new_node.depth-1, 1)
                pnode = new_node
        self.print_cur_info(pnode)      #输出最后一个node的信息
        print("输出结束")
        return 0

class Reader:

    _meta = {}
    data = b""

    _v4offset = 0
    _v6offsetCache = {}

    def __init__(self, name):
        self._v4offset = 0
        self._v6offsetCache = {}

        file = open(name, "rb")
        self.data = file.read()
        self._file_size = len(self.data)
        file.close()
        meta_length = bytes2long(self.data[0], self.data[1], self.data[2], self.data[3])
        if sys.version_info < (3,0):
            meta = json.loads(str(self.data[4:meta_length + 4]))
        else:
            meta = json.loads(str(self.data[4:meta_length + 4], 'utf-8'))

        self._meta = MetaData(**meta)
        if len(self._meta.languages) == 0 or len(self._meta.fields) == 0:
            raise DatabaseError("database meta error")
        if self._file_size != (4 + meta_length + self._meta.total_size):
            raise DatabaseError("database size error")

        self.data = self.data[4+meta_length:]

    def _read_node(self, node, idx):
        off = idx * 4 + node * 8
        return bytes2long(self.data[off], self.data[off + 1], self.data[off + 2], self.data[off + 3])

    def _find_node(self, ip):

        if ip.version == 6:
            bit_count = 128
        else:
            bit_count = 32

        idx = 0
        node = 0
        key = ip.packed[0:2]
        if bit_count == 32:
            if self._v4offset == 0:
                i = 0
                while i < 96:
                    if i >= 80:
                        node = self._read_node(node, 1)
                    else:
                        node = self._read_node(node, 0)
                    i += 1
                self._v4offset = node
            else:
                node = self._v4offset
        else:
            val = self._v6offsetCache.get(key, -1)
            if val > -1:
                idx = 16
                node = val

        packed = bytearray(ip.packed)
        while idx < bit_count:
            if node > self._meta.node_count:
                break
            node = self._read_node(node, (1 & (packed[idx >> 3] >> 7 - (idx % 8))))
            idx += 1
            if idx == 16 and bit_count == 128:
                self._v6offsetCache[key] = node

        if node > self._meta.node_count:
            return node
        raise IPNotFound("ip not found")

    def _resolve(self, node):
        resolved = node - self._meta.node_count + self._meta.node_count * 8
        size = bytes2long(0, 0, self.data[resolved], self.data[resolved + 1])
        if (resolved+2+size) > len(self.data):
            raise DatabaseError("database is error")
        return self.data[resolved+2:resolved+2+size]

    def find(self, addr, language):
        off = self._meta.languages.get(language)
        if off is None:
            raise NoSupportLanguageError(language + " is not support")

        ipv = ipaddress.ip_address(addr)
        if ipv.version == 6:
            if self.is_support_ipv6() is False:
                raise NoSupportIPv6Error("database is not support ipv6")
        elif ipv.version == 4:
            if self.is_support_ipv4() is False:
                raise NoSupportIPv4Error("database is not support ipv4")

        node = self._find_node(ipv)
        if node is None:
            return None

        bs = self._resolve(node)
        if bs is None:
            return None

        tmp = bs.decode("utf-8").split("\t")
        end = off + len(self._meta.fields)
        if len(tmp) < end:
            raise DatabaseError("database is error")

        return tmp[off:off+len(self._meta.fields)]

    def find_map(self, addr, language):
        loc = self.find(addr, language)
        if loc is None:
            return None
        m = {}
        for idx, value in enumerate(self._meta.fields):
            m[value] = loc[idx]
        return m


    def get_meta_data(self):
        return self._meta

    def support_languages(self):
        ls = []
        for p in self._meta.languages:
            ls.append(p)
        return ls

    def support_fields(self):
        return self._meta.fields

    def is_support_ipv4(self):
        return (self._meta.ip_version & 0x01) == 0x01

    def is_support_ipv6(self):
        return (self._meta.ip_version & 0x02) == 0x02

    def build_utc_time(self):
        return self._meta.build
