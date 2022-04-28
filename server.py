from userAuth import XiaoHuanServer


if __name__ == "__main__":
    xhs = XiaoHuanServer(debug=True)
    xhs.run_server()