from main import app, socketio

if __name__ == "__main__":
    socketio.run(app, 
                host='0.0.0.0',
                port=80,
                debug=False,
                allow_unsafe_werkzeug=True) 