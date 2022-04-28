from userAuth import HYClient


if __name__ == "__main__":
    hyc = HYClient(debug=True)
    hyc.connect_server()
