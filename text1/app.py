from flask import Flask, render_template, request, jsonify
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import base64
import json

app = Flask(__name__)

class CPABEPolicy:
    def __init__(self, policy_str):
        self.policy = self.parse_policy(policy_str)
    
    def parse_policy(self, policy_str):
        """解析策略字符串为策略树"""
        try:
            # 支持 AND 和 OR 操作
            policy_dict = json.loads(policy_str)
            if not isinstance(policy_dict, dict):
                raise ValueError("策略必须是JSON对象格式")
            
            # 验证策略格式
            self._validate_policy(policy_dict)
            return policy_dict
        except json.JSONDecodeError:
            raise ValueError("无效的策略格式")
    
    def _validate_policy(self, policy):
        """验证策略格式是否正确"""
        if 'operator' not in policy or 'conditions' not in policy:
            raise ValueError("策略必须包含 'operator' 和 'conditions' 字段")
        
        if policy['operator'] not in ['AND', 'OR']:
            raise ValueError("操作符必须是 'AND' 或 'OR'")
        
        for condition in policy['conditions']:
            if isinstance(condition, dict):
                self._validate_policy(condition)
            elif not isinstance(condition, str):
                raise ValueError("条件必须是字符串或嵌套策略")

def check_access(user_attributes, policy):
    """增强的访问控制检查"""
    try:
        policy_obj = CPABEPolicy(policy)
        return evaluate_policy(policy_obj.policy, user_attributes)
    except Exception as e:
        return False

def evaluate_policy(policy, attributes):
    """评估策略树"""
    operator = policy['operator']
    conditions = policy['conditions']
    
    results = []
    for condition in conditions:
        if isinstance(condition, dict):
            # 递归评估嵌套策略
            result = evaluate_policy(condition, attributes)
        else:
            # 评估单个条件
            attr, op, value = parse_condition(condition)
            result = evaluate_condition(attributes.get(attr), op, value)
        results.append(result)
    
    # 根据操作符计算最终结果
    if operator == 'AND':
        return all(results)
    elif operator == 'OR':
        return any(results)

def parse_condition(condition):
    """解析条件字符串"""
    operators = ['=', '!=', '>', '<', '>=', '<=']
    for op in operators:
        if op in condition:
            attr, value = condition.split(op)
            return attr.strip(), op, value.strip()
    raise ValueError(f"无效的条件格式: {condition}")

def evaluate_condition(attr_value, op, required_value):
    """评估单个条件"""
    if attr_value is None:
        return False
    
    try:
        # 尝试数值比较
        if str(attr_value).replace('.', '').isdigit() and str(required_value).replace('.', '').isdigit():
            attr_value = float(attr_value)
            required_value = float(required_value)
    except ValueError:
        pass
    
    if op == '=':
        return attr_value == required_value
    elif op == '!=':
        return attr_value != required_value
    elif op == '>':
        return attr_value > required_value
    elif op == '<':
        return attr_value < required_value
    elif op == '>=':
        return attr_value >= required_value
    elif op == '<=':
        return attr_value <= required_value
    
    return False

# 加密数据函数
def encrypt_data(key, data):
    # 使用 AES CBC 模式加密数据
    cipher = AES.new(key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(data.encode(), AES.block_size))
    # 返回加密后的数据，包含 IV（初始化向量）
    return base64.b64encode(cipher.iv + ct_bytes).decode('utf-8')


# 解密数据函数
def decrypt_data(key, enc_data):
    # 解码传输的加密数据
    enc_data = base64.b64decode(enc_data)
    iv = enc_data[:16]  # 前 16 字节是 IV
    ct = enc_data[16:]  # 剩余是加密的内容
    cipher = AES.new(key, AES.MODE_CBC, iv)
    # 解密并去除填充
    pt = unpad(cipher.decrypt(ct), AES.block_size)
    return pt.decode('utf-8')


@app.route('/')
def index():
    # 渲染首页模板
    return render_template('index.html')


@app.route('/encrypt', methods=['POST'])
def encrypt():
    try:
        # 从前端获取数据
        data = request.json['data']
        policy = request.json['policy']
        user_attributes = request.json['user_attributes']

        # 验证用户是否符合访问策略
        if not check_access(user_attributes, policy):
            return jsonify({"error": "Access denied, policy not satisfied"}), 403

        # 生成随机密钥（AES 128 位）
        key = get_random_bytes(16)

        # 加密数据
        encrypted_data = encrypt_data(key, data)

        # 返回加密数据和密钥（密钥经过 base64 编码）
        return jsonify({
            "encrypted_data": encrypted_data,
            "key": base64.b64encode(key).decode('utf-8')  # 返回加密密钥
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 400


@app.route('/decrypt', methods=['POST'])
def decrypt():
    try:
        # 获取加密数据和密钥
        enc_data = request.json['encrypted_data']
        key_base64 = request.json['key']
        key = base64.b64decode(key_base64)  # 解码密钥

        # 解密数据
        decrypted_data = decrypt_data(key, enc_data)

        # 返回解密后的数据
        return jsonify({"decrypted_data": decrypted_data})
    except Exception as e:
        return jsonify({"error": str(e)}), 400


if __name__ == '__main__':
    # 启动 Flask 应用
    app.run(debug=True)
