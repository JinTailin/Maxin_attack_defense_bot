      
import requests
import json
import time

BASE_URL = "http://10.1.0.220:9002/api"
# 请根据实际端口修改BASE_URL

# 【重要！！！】 请修改 USER_NAME（把?替换为你的组号） 和 TOKEN（你的token）
USER_NAME = "Group10"
TOKEN = "svrdAPQFp0I9K0VSeEa9G0Gvy9aU4vSbI8Ft4QKoRzRq0-K8ayGs4xKhdNmh8xzl"

# 1. 创建数据库
def test_create_database(metric_type="cosine"):
    db_name = f"student_{USER_NAME}_{int(time.time())}"
    resp = requests.post(f"{BASE_URL}/databases", json={"database_name": db_name, "token": TOKEN, "metric_type": metric_type})
    print("创建数据库:", resp.status_code, resp.json())
    assert resp.status_code == 200
    return db_name, metric_type

# 2. 获取数据库列表
def test_get_databases():
    resp = requests.get(f"{BASE_URL}/databases", params={"token": TOKEN})
    print("获取数据库列表:", resp.status_code, resp.json())
    assert resp.status_code == 200
    return resp.json()["databases"]

# 3. 上传文件
def test_upload_file(db_name):
    payload = {
        "files": [
            {"file": "hello world, 网络安全测试", "metadata": {"description": "测试文件1"}},
            {"file": "第二条测试文本", "metadata": {"description": "测试文件2"}}
        ],
        "token": TOKEN
    }
    resp = requests.post(f"{BASE_URL}/databases/{db_name}/files", json=payload)
    print("上传文件:", resp.status_code, resp.json())
    assert resp.status_code == 200
    return resp.json()["file_ids"][0]  # 取第一个文件的id做后续测试

# 4. 查询数据库文件
def test_get_files(db_name):
    resp = requests.get(f"{BASE_URL}/databases/{db_name}/files", params={"token": TOKEN})
    print("查询数据库文件:", resp.status_code, resp.json())
    assert resp.status_code == 200
    return resp.json()["files"]

# 5. 相似文件检索
def test_search(db_name, metric_type, file_id):
    print("\n合法expr测试:")
    payload = {
        "token": TOKEN,
        "query": "网络安全",
        "top_k": 3,
        "metric_type": metric_type,
        "expr": f"file_id == {file_id}"
    }
    resp = requests.post(f"{BASE_URL}/databases/{db_name}/search", json=payload)
    print("合法expr相似文件检索:", resp.status_code, resp.json())
    assert resp.status_code == 200
    print("\n不合法expr测试:")
    payload["expr"] = "not_a_field == 123"
    resp = requests.post(f"{BASE_URL}/databases/{db_name}/search", json=payload)
    try:
        print("不合法expr相似文件检索:", resp.status_code, resp.json())
    except Exception:
        print("不合法expr相似文件检索: 非法响应", resp.status_code, resp.text)

# 6. 删除文件
def test_delete_file(db_name, file_id):
    resp = requests.delete(f"{BASE_URL}/databases/{db_name}/files/{file_id}", params={"token": TOKEN})
    print("删除文件:", resp.status_code, resp.json())
    assert resp.status_code == 200

# 7. 对话接口
def test_dialogue():
    payload = {
        "user_input": "请介绍一下网络安全的基本概念。",
        "token": TOKEN
    }
    resp = requests.post(f"{BASE_URL}/dialogue", json=payload)
    print("对话接口:", resp.status_code, resp.json())
    assert resp.status_code == 200

if __name__ == "__main__":
    # db_name, metric_type = test_create_database(metric_type="cosine")
    # dbs = test_get_databases()
    # file_id = test_upload_file(db_name)
    # time.sleep(2)  # 等待Milvus flush
    # files = test_get_files(db_name)
    # test_search(db_name, metric_type, file_id)
    # test_delete_file(db_name, file_id)
    test_dialogue()
    print("所有接口测试完成！") 

    