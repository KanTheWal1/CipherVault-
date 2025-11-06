from website import *

app = build_app()

if __name__ == '__main__': 
    try:
    # app.run(debug=True, ssl_context=('website/Certs/cert.pem', 'website/Certs/key.pem'))
      app.run(debug=True) # Turn off , ssl_context = "adhoc" for production.
    except Exception as e:
        print(f"Error starting the app: {e}")
        