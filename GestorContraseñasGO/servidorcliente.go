package main

import (
	"io/ioutil"
	"sds/httpscerts"

	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"regexp"
	"time"
)

/*type usuario struct {
	id int
	user string
	pass string
	map[string]string
}

map[int] usuario*/

// función para comprobar errores (ahorra escritura)
func chk(e error) {
	if e != nil {
		panic(e)
	}
}

// respuesta del servidor
type resp struct {
	Ok  bool   // true -> correcto, false -> error
	Msg string // mensaje adicional
}

// función para escribir una respuesta del servidor
func response(w io.Writer, ok bool, msg string) {
	r := resp{Ok: ok, Msg: msg}    // formateamos respuesta
	rJSON, err := json.Marshal(&r) // codificamos en JSON
	chk(err)                       // comprobamos error
	w.Write(rJSON)                 // escribimos el JSON resultante
}

/*func redirectToHttps(w http.ResponseWriter, r *http.Request) {
	// Redirect the incoming HTTP request. Note that "127.0.0.1:8081" will only work if you are accessing the server from your local machine.
	http.Redirect(w, r, "https://127.0.0.1:8081"+r.RequestURI, http.StatusMovedPermanently)
}
*/

func main() {

	fmt.Println("Un ejemplo de server/cliente mediante TLS/HTTP en Go.")
	s := "Introduce srv para funcionalidad de servidor y cli para funcionalidad de cliente"

	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "srv":
			fmt.Println("Entrando en modo servidor...")
			server()
		case "cli":
			fmt.Println("Entrando en modo cliente...")
			client()
		default:
			fmt.Println("Parámetro '", os.Args[1], "' desconocido. ", s)
		}
	} else {
		fmt.Println(s)
	}
}

/**
SERVIDOR
**/

func server() {

	stopChan := make(chan os.Signal)
	signal.Notify(stopChan, os.Interrupt)

	// Check if the cert files are available.
	err := httpscerts.Check("cert.pem", "key.pem")
	// If they are not available, generate new ones.
	if err != nil {
		err = httpscerts.Generate("cert.pem", "key.pem", "127.0.0.1:8081")
		if err != nil {
			log.Fatal("Error: Couldn't create https certs.")
		}
	}

	mux := http.NewServeMux()
	mux.Handle("/", http.HandlerFunc(handler))
	mux.Handle("/login", http.HandlerFunc(login))

	srv := &http.Server{Addr: ":8081", Handler: mux}

	go func() {
		if err := srv.ListenAndServeTLS("cert.pem", "key.pem"); err != nil {
			log.Printf("listen: %s\n", err)
		}
	}()
	//http.ListenAndServe(":8080", http.HandlerFunc(redirectToHttps))

	/*http.HandleFunc("/", handler)
	http.HandleFunc("/hello", HelloServer)
	http.HandleFunc("/datos", Datos)*/

	// Start the HTTPS server in a goroutine
	//go http.ListenAndServeTLS(":8081", "cert.pem", "key.pem", nil)
	// Start the HTTP server and redirect all incoming connections to HTTPS

	/*http.HandleFunc("/bar", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "Hello, %q", html.EscapeString(r.URL.Path))


	})*/

	<-stopChan // espera señal SIGINT
	log.Println("Apagando servidor ...")

	// apagar servidor de forma segura
	ctx, fnc := context.WithTimeout(context.Background(), 5*time.Second)
	fnc()
	srv.Shutdown(ctx)

	log.Println("Servidor detenido correctamente")

}

func login(w http.ResponseWriter, req *http.Request) {
	fmt.Fprintf(w, "Estamos en el login")
	req.ParseForm()                              // es necesario parsear el formulario
	w.Header().Set("Content-Type", "text/plain") // cabecera estándar

	switch req.Form.Get("cmd") { // comprobamos comando desde el cliente
	case "hola": // ** registro
		response(w, true, "Hola "+req.Form.Get("mensaje"))
	default:
		response(w, false, "Comando inválido")
	}
}

func handler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "Hi there BRO!")
}

/**
CLIENTE

**/

func menu() {
	var input int
	n, err := fmt.Scanln(&input)
	if n < 1 || err != nil {
		fmt.Println("invalid input")
		return
	}
	switch input {
	case 1:
		fmt.Println("hi")
		pruebaPeti()
	case 2:
		fmt.Println("hi")
	case 3:
		os.Exit(2)
	}
}

func client() {

	for {
		fmt.Println("Bienvenido al menu")
		fmt.Println("1.Iniciar Sesion")
		fmt.Println("2.Registrarse")
		fmt.Println("3.Salir")
		menu()
	}
}

func cleanUp(s string) string {
	re := regexp.MustCompile(`\b(\\\d\d\d)`)
	return re.ReplaceAllStringFunc(s, func(s string) string {
		return `\u0` + s[1:]
	})
}

func pruebaPeti() {
	/* creamos un cliente especial que no comprueba la validez de los certificados
	esto es necesario por que usamos certificados autofirmados (para pruebas) */
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}

	// ** ejemplo de registro
	data := url.Values{}             // estructura para contener los valores
	data.Set("cmd", "hola")          // comando (string)
	data.Set("mensaje", "miusuario") // usuario (string)

	r, err := client.PostForm("https://localhost:8081/login", data) // enviamos por POST
	chk(err)
	//io.Copy(os.Stdout, r.Body) // mostramos el cuerpo de la respuesta (es un reader)
	//fmt.Println()

	b, err := ioutil.ReadAll(r.Body)
	defer r.Body.Close()
	chk(err)

	var respu resp
	json.Unmarshal(b, &respu)

	fmt.Println("Ok = %t", b)

	//io.Copy(os.Stdout, r.Body) // mostramos el cuerpo de la respuesta (es un reader)
	//fmt.Println()
	//body := bytes.TrimPrefix(r.Body, []byte("\xef\xbb\xbf"))
	/*b, err := ioutil.ReadAll(r.Body)
	defer r.Body.Close()
	chk(err)

	bfinal := string(b)
	iri := cleanUp(bfinal)
	//fmt.Println(b)
	//var st string
	//st = "{\"Ok\":true,\"Msg\":\"Hola miusuario\"}"
	bytes := []byte(iri)

	//respuestaServer := r.Body.Read
	var respu resp
	//r := resp{Ok: ok, Msg: msg}    // formateamos respuesta

	//err = json.Unmarshal(bytes, &respu) // codificamos en JSON
	err = json.Unmarshal(bytes, &respu)
	chk(err)
	//respuestaSerer := r.Body.readAll()

	if respu.Ok == true {
		fmt.Println("Iniciando sesion")
	}
	/*resp := r.Body.Get("Ok")
	if resp == true {
		fmt.Println("Iniciando sesion")
	}*/

	//fmt.Println()
}
