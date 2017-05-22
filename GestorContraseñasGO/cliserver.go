/*

Este programa muestra comunicarse entre cliente y servidor,
así como el uso de HTTPS (HTTP sobre TLS) mediante certificados (autofirmados).

Conceptos: JSON, TLS

*/

package main

import (
	"bufio"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/tls"
	"encoding/base32"
	"encoding/base64"
	"strings"
	"syscall"

	"golang.org/x/crypto/ssh/terminal"
	//"encoding/gob"
	//"bytes"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/smtp"
	"net/url"
	"os"
	"os/signal"
	"sds/httpscerts"

	//"text/template"
	//"strconv"
	//"strings"
	"time"
)

type usuario struct {
	Id          int
	User        string
	Pass        string
	PassCifrado string
	Correo      string
	Pin         string
	Structpass  map[string]Passwords
}

type Passwords struct {
	User       string
	Pass       string
	Comentario string
}

type Cookie struct {
	Id         int
	name       string
	ultimapeti time.Time
}

var usuarios map[string]usuario
var cookies map[string]Cookie
var StdChars = []byte("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()-_=+,.?/:;{}[]`~")
var mainPass string = "WZRHGrsBESr8wYFZ9sx0tPURuZgG2lmzyvWpwXPKz8U="

func init() {
	usuarios = make(map[string]usuario)
	cookies = make(map[string]Cookie)

	/*var userTest usuario
	userTest.Id = 0
	userTest.User = "juan"
	userTest.Pass = "7QjCkNfiL3uzJLFcutzjWws0hWT9LV+VdSOI2G1xvMo="

	usuarios["juan"] = userTest
	fmt.Println("Añadido usuario Testing juan")*/
	//LoadJsonFile(usuarios, "mydb.json")
	//fmt.Println("LALALAND1: ")
	//fmt.Println(usuarios)

	//err := Load(file, &usuarios)
	//chk(err)
	//fmt.Println(usuarios)
	//usuarios[0] = 0
	//test["bar"] = 1
}

//var map[int] usuario

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

func encriptafichero() {
	file, e := ioutil.ReadFile("mydb.json")
	if e != nil {
		fmt.Printf("File error: %v\n", e)
		os.Exit(1)
	}

	originalText := string(file)

	//key := []byte("AES256Key-32Characters1234567890")
	keyClient := sha512.Sum512([]byte(mainPass))
	keyData := keyClient[32:64] // una mitad para cifrar datos (256 bits)

	// encrypt value to base64
	cryptoText := encrypt(keyData, originalText)
	fmt.Println(cryptoText)

	f, err := os.Create("mydb.json")
	chk(err)
	w := bufio.NewWriter(f)
	n4, err := w.WriteString(cryptoText)
	chk(err)
	fmt.Printf("wrote %d bytes\n", n4)
	w.Flush()
}

func desencriptafichero() {
	file, e := ioutil.ReadFile("mydb.json")
	if e != nil {
		fmt.Printf("File error: %v\n", e)
		os.Exit(1)
	}

	originalText := string(file)
	fmt.Println(originalText)

	//key := []byte("AES256Key-32Characters1234567890")
	keyClient := sha512.Sum512([]byte(mainPass))
	keyData := keyClient[32:64] // una mitad para cifrar datos (256 bits)
	// encrypt base64 crypto to original value
	text := decrypt(keyData, originalText)
	fmt.Printf(text)

	f, err := os.Create("mydb.json")
	chk(err)
	w := bufio.NewWriter(f)
	n4, err := w.WriteString(text)
	chk(err)
	fmt.Printf("wrote %d bytes\n", n4)
	w.Flush()
}

// encrypt string to base64 crypto using AES
func encrypt(key []byte, text string) string {
	// key := []byte(keyText)
	plaintext := []byte(text)

	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	// The IV needs to be unique, but not secure. Therefore it's common to
	// include it at the beginning of the ciphertext.
	ciphertext := make([]byte, aes.BlockSize+len(plaintext))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		panic(err)
	}

	//Cipher feedback (CFB):
	stream := cipher.NewCFBEncrypter(block, iv) //Utilizamos método CFB
	stream.XORKeyStream(ciphertext[aes.BlockSize:], plaintext)

	// convert to base64
	return base64.StdEncoding.EncodeToString(ciphertext)
	//return base64.URLEncoding.EncodeToString(ciphertext)
}

// decrypt from base64 to decrypted string
func decrypt(key []byte, cryptoText string) string {
	ciphertext, err := base64.StdEncoding.DecodeString(cryptoText) // recupera el formato original
	//chk(err)                                                       // comprobamos el error
	//ciphertext, _ := base64.URLEncoding.DecodeString(cryptoText)

	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	// The IV needs to be unique, but not secure. Therefore it's common to
	// include it at the beginning of the ciphertext.
	if len(ciphertext) < aes.BlockSize {
		panic("ciphertext too short")
	}
	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]

	stream := cipher.NewCFBDecrypter(block, iv) //Utilizamos método CFB

	// XORKeyStream can work in-place if the two arguments are the same.
	stream.XORKeyStream(ciphertext, ciphertext)

	return fmt.Sprintf("%s", ciphertext)
}

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

/***
SERVIDOR
***/

func checkInicioSesion(user string, pass string) bool {

	var encontrado bool
	encontrado = false
	//Mirar en la DB si existe
	// ...
	for clave, usuario := range usuarios {
		fmt.Println("key[%s] value[%s]\n", clave, usuario)
		fmt.Println("USUARIO: " + usuario.Pass)
		fmt.Println("USUARIO2: " + pass)

		if usuario.User == user && usuario.Pass == pass {
			//response(w, true, "Hola 2323")
			encontrado = true
			fmt.Println("USUARIO ENCOONTRADO")
			break
		}

	}
	return encontrado
}

func verificaPin(pin string, us string) bool {

	var token string
	for clave, user := range usuarios {
		fmt.Println("key[%s] value[%s]\n", clave, user) //NO COMENTAR O NO COMPILA
		if user.User == us {
			token = user.Pin
		}
	}
	fmt.Println("ESTO ES EL PIN " + pin)
	fmt.Println("ESTO ES EL TOKEN " + token)

	if pin == token {
		return true
	} else {
		return false
	}
}

func checkRegistro(user string, pass string, correo string) bool {
	var nuevoRegistro bool
	nuevoRegistro = false

	if checkInicioSesion(user, pass) == false {
		var nuevoUser usuario
		nuevoUser.Id = len(usuarios)
		nuevoUser.User = user
		nuevoUser.Pass = pass
		nuevoUser.Correo = correo
		nuevoUser.Structpass = make(map[string]Passwords) //Inicializamos el mapa de contraseñas en REGISRRO, para tenerlo disponible más adelante
		var pasi = generaRandomPass()
		if pasi != "error" {
			nuevoUser.PassCifrado = generaRandomPass()

			usuarios[user] = nuevoUser
			fmt.Println("Añadido usuario " + user + " con pass: " + pass)

			nuevoRegistro = true
		}

	}

	return nuevoRegistro
}

//Genera un []byte de bytes aleatorios, se pasa a base64 y despues se saca un sha, se pasa a b64 y se almacena.
func generaRandomPass() string {

	b := make([]byte, 15)
	_, err := rand.Read(b)
	if err != nil {
		fmt.Println("error:", err)
		return "error"
	}
	// The slice should now contain random bytes instead of only zeroes.
	/*fmt.Println(bytes.Equal(b, make([]byte, 15)))
	fmt.Println("RAND: ")
	fmt.Println(b)*/
	randomenBase := base64.StdEncoding.EncodeToString(b)
	//fmt.Println("RAND2: " + randomenBase)

	sha_256 := sha256.New()
	sha_256.Write([]byte(randomenBase))
	sha_bytes := sha_256.Sum(nil)
	//fmt.Printf("sha256:\t%x\n", sha_bytes)
	pass_sha := base64.StdEncoding.EncodeToString(sha_bytes)

	return pass_sha
}

func SaveJsonFile(v interface{}, path string) {
	fo, err := os.Create(path)
	if err != nil {
		panic(err)
	}
	defer fo.Close()
	e := json.NewEncoder(fo)
	if err := e.Encode(v); err != nil {
		panic(err)
	}
	encriptafichero()
}

func LoadJsonFile(v interface{}, path string) {

	desencriptafichero()
	file, e := ioutil.ReadFile(path)
	if e != nil {
		fmt.Printf("File error: %v\n", e)
		os.Exit(1)
	}
	fmt.Printf("%s\n", string(file))

	//m := new(Dispatch)
	//var m interface{}
	//var jsontype jsonobject
	json.Unmarshal(file, &usuarios)
	fmt.Printf("Results: %v\n", usuarios)

}

//Almacenar la DB en un fichero
func guardarDB() {
	SaveJsonFile(usuarios, "mydb.json")
}

// gestiona el modo servidor
func server() {

	fmt.Println("Contraseña: ")
	bytePassword, erro := terminal.ReadPassword(int(syscall.Stdin))
	if erro == nil {
		fmt.Println("\nPassword typed: " + string(bytePassword))
	}
	byteString := string(bytePassword)

	sha_256 := sha256.New()
	sha_256.Write([]byte(byteString))
	sha_bytes := sha_256.Sum(nil)
	//fmt.Printf("sha256:\t%x\n", sha_bytes)

	pass_sha := base64.StdEncoding.EncodeToString(sha_bytes)

	if pass_sha != mainPass {
		//fmt.Println("ContraseñaSHA: " + pass_sha)
		//fmt.Println("ContraseñaSHA2: " + mainPass)
		fmt.Println("NO TIENES PERMISOS")
		return
	}

	LoadJsonFile(usuarios, "mydb.json")
	//fmt.Println("LALALAND1: ")
	//fmt.Println(usuarios)

	// suscripción SIGINT
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

	srv := &http.Server{Addr: ":8081", Handler: mux}

	go func() {
		if err := srv.ListenAndServeTLS("cert.pem", "key.pem"); err != nil {
			log.Printf("listen: %s\n", err)
		}
	}()

	<-stopChan // espera señal SIGINT
	log.Println("Apagando servidor ...")

	guardarDB()

	// apagar servidor de forma segura
	ctx, fnc := context.WithTimeout(context.Background(), 5*time.Second)
	fnc()
	srv.Shutdown(ctx)

	log.Println("Servidor detenido correctamente")
}

func pedircontraseñasS(usu string) string {
	var stripass []string
	for clave, user := range usuarios {
		fmt.Println("key[%s] value[%s]\n", clave, user) //NO COMENTAR O NO COMPILA
		//fmt.Println("USUARIO: " + user.User)
		if user.User == usu {

			//Recorro todas las contraseñas almacenadas en el usuario
			for c, p := range usuarios[usu].Structpass {
				fmt.Println("key[%s] \n", c) //NO COMENTAR O NO COMPILA

				stripass = append(stripass, p.Comentario) //Añado el Comentario al array

			}
			//fmt.Println(usuarios[usu].Structpass)
		}
	}
	var solucion = ""
	solucion = strings.Join(stripass, "\n") //Join, unifica un array en un string, separado por un caracter dado

	return solucion
}

func nuevacontraseñaS(usuario string, us string, pass string, comen string) {
	for clave, user := range usuarios {
		fmt.Println("key[%s] value[%s]\n", clave, user) //NO COMENTAR O NO COMPILA
		//fmt.Println("USUARIO: " + user.User)
		if user.User == usuario {
			var nuevapass Passwords
			nuevapass.Pass = encode64(encryptCTR([]byte(pass), decode64(user.PassCifrado)))
			nuevapass.User = us
			nuevapass.Comentario = comen
			usuarios[usuario].Structpass[comen] = nuevapass //utilizamos el Comentario como clave del mapa
		}
	}
}

func eliminarcontraseñaS(us string, comen string) {
	for clave, user := range usuarios {
		fmt.Println("key[%s] value[%s]\n", clave, user) //NO COMENTAR O NO COMPILA
		if user.User == us {
			fmt.Println("la clave" + usuarios[us].Structpass[comen].Comentario + " va a ser eliminada")
			delete(usuarios[us].Structpass, comen)
		}
	}
}

// función para codificar de []bytes a string (Base64)
func encode64(data []byte) string {
	return base64.StdEncoding.EncodeToString(data) // sólo utiliza caracteres "imprimibles"
}

// función para decodificar de string a []bytes (Base64)
func decode64(s string) []byte {
	b, err := base64.StdEncoding.DecodeString(s) // recupera el formato original
	chk(err)                                     // comprobamos el error
	return b                                     // devolvemos los datos originales
}

// función para cifrar (con AES en este caso), adjunta el IV al principio
func encryptCTR(data, key []byte) (out []byte) {
	out = make([]byte, len(data)+16)    // reservamos espacio para el IV al principio
	rand.Read(out[:16])                 // generamos el IV
	blk, err := aes.NewCipher(key)      // cifrador en bloque (AES), usa key
	chk(err)                            // comprobamos el error
	ctr := cipher.NewCTR(blk, out[:16]) // cifrador en flujo: modo CTR, usa IV
	ctr.XORKeyStream(out[16:], data)    // ciframos los datos
	return
}

// función para descifrar (con AES en este caso)
func decryptCTR(data, key []byte) (out []byte) {
	out = make([]byte, len(data)-16)     // la salida no va a tener el IV
	blk, err := aes.NewCipher(key)       // cifrador en bloque (AES), usa key
	chk(err)                             // comprobamos el error
	ctr := cipher.NewCTR(blk, data[:16]) // cifrador en flujo: modo CTR, usa IV
	ctr.XORKeyStream(out, data[16:])     // desciframos (doble cifrado) los datos
	return
}

func recordarContrasenaS(usuario string, comen string) string {
	fmt.Println("USUARIO: " + usuario)
	fmt.Println("COMENTARIO: " + comen)

	var solucion = "NO TIENES CONTRASEÑAS CON ESA DESCRIPCION"

	for c, p := range usuarios[usuario].Structpass {
		fmt.Println("key[%s] \n", c)

		if strings.ToLower(p.Comentario) == strings.ToLower(comen) {
			solucion = "Contraseña de " + p.Comentario + ": "
			solucion += string(decryptCTR(decode64(p.Pass), decode64(usuarios[usuario].PassCifrado))) + "\n" // decodificamos y desencriptamos las contraseñas
			solucion += "Usuario de " + p.Comentario + ": " + p.User
		}

	}

	return solucion
}

func cambiarContrasenaS(usuario string, us string, pass string, comen string) {
	for clave, user := range usuarios {
		fmt.Println("key[%s] value[%s]\n", clave, user) //NO COMENTAR O NO COMPILA
		//fmt.Println("USUARIO: " + user.User)
		if user.User == usuario {
			var nuevapass Passwords
			nuevapass.Pass = encode64(encryptCTR([]byte(pass), decode64(user.PassCifrado)))
			nuevapass.User = us
			nuevapass.Comentario = comen
			usuarios[usuario].Structpass[comen] = nuevapass //utilizamos el Comentario como clave del mapa
		}
	}
}

func getToken(length int) string {
	randomBytes := make([]byte, 32)
	_, err := rand.Read(randomBytes)
	if err != nil {
		panic(err)
	}
	return base32.StdEncoding.EncodeToString(randomBytes)[:length]
}

func enviarmail(us string) {

	var correousu string

	token := getToken(5)
	fmt.Println("Here is a random token : ", token)

	for clave, user := range usuarios {
		fmt.Println("key[%s] value[%s]\n", clave, user) //NO COMENTAR O NO COMPILA
		if user.User == us {
			correousu = user.Correo

			var nuevotoken usuario
			nuevotoken = user
			nuevotoken.Pin = token
			usuarios[us] = nuevotoken
		}
	}

	from := "sdsservidor@gmail.com"
	pass := "sds12345"
	to := correousu

	msg := "From: " + from + "\n" +
		"To: " + to + "\n" +
		"Subject: Autenticacion SDS \n\n" +
		"HOLA tu clave es: " + token

	err := smtp.SendMail("smtp.gmail.com:587", // in our case, "smtp.google.com:587"
		smtp.PlainAuth("", from, pass, "smtp.gmail.com"),
		from,
		[]string{to},
		[]byte(msg))

	if err != nil {
		log.Print("ERROR: attempting to send a mail ", err)
	}
}

func handler(w http.ResponseWriter, req *http.Request) {
	req.ParseForm()                              // es necesario parsear el formulario
	w.Header().Set("Content-Type", "text/plain") // cabecera estándar

	switch req.Form.Get("cmd") { // comprobamos comando desde el cliente

	case "hola": // ** registro
		response(w, true, "Hola "+req.Form.Get("mensaje"))

	case "iniciarSesion":
		//checkInicioSesion(w, req.Form.Get("usuario"), req.Form.Get("password"))
		if checkInicioSesion(req.Form.Get("usuario"), req.Form.Get("password")) == true {
			//crearcookie(req.Form.Get("usuario"))
			enviarmail(req.Form.Get("usuario"))
			//response(w, true, "Hola "+req.Form.Get("usuario"))
			response(w, true, "Introduce la clave que has recibido en tu correo:")
		} else {
			response(w, false, "ERROR: Usuario o contraseña inválidos")
		}

	case "verificarpin":
		if verificaPin(req.Form.Get("pin"), req.Form.Get("usuario")) == true {
			crearcookie(req.Form.Get("usuario"))
			response(w, true, "Hola "+req.Form.Get("usuario"))
		} else {
			response(w, false, "ERROR: Usuario o contraseña inválidos")
		}

	case "registro":
		if checkRegistro(req.Form.Get("usuario"), req.Form.Get("password"), req.Form.Get("correo")) == true {
			response(w, true, "Registro completado.")
		} else {
			response(w, false, "ERROR: Ya existe un usuario con esos datos.")
		}

	case "pedircontraseñas":
		if comprobartime(req.Form.Get("usuario")) {
			contrase := pedircontraseñasS(req.Form.Get("usuario"))
			response(w, true, contrase)
		} else {
			response(w, false, "ERROR: Tiempo de cookie expirado.")
		}

	case "nuevacontraseña":
		if comprobartime(req.Form.Get("usuario")) {
			nuevacontraseñaS(req.Form.Get("usuario"), req.Form.Get("us"), req.Form.Get("pass"), req.Form.Get("comentario"))
			response(w, true, "Contraseña introducida.")
		} else {
			response(w, false, "ERROR: Tiempo de cookie expirado.")
		}

	case "eliminarcontraseñas":
		if comprobartime(req.Form.Get("usuario")) {
			eliminarcontraseñaS(req.Form.Get("usuario"), req.Form.Get("comentario"))
			response(w, true, "Contraseña eliminada.")
		} else {
			response(w, false, "ERROR: Tiempo de cookie expirado.")
		}

	case "recordarcontrasena":
		if comprobartime(req.Form.Get("usuario")) {
			contrasena := recordarContrasenaS(req.Form.Get("usuario"), req.Form.Get("comentario"))
			response(w, true, contrasena)
		} else {
			response(w, false, "ERROR: Tiempo de cookie expirado.")
		}

	case "cambiarcontraseña":
		if comprobartime(req.Form.Get("usuario")) {
			cambiarContrasenaS(req.Form.Get("usuario"), req.Form.Get("us"), req.Form.Get("pass"), req.Form.Get("comentario"))
			response(w, true, "Contraseña cambiada.")
		} else {
			response(w, false, "ERROR: Tiempo de cookie expirado.")
		}

	default:
		response(w, false, "Comando inválido")
	}

}

func crearcookie(usu string) {
	var nuevaCookie Cookie
	nuevaCookie.Id = len(cookies)
	nuevaCookie.name = usu
	nuevaCookie.ultimapeti = time.Now()
	cookies[usu] = nuevaCookie
	fmt.Println("COOKIE creada para el user " + usu)
}

func eliminarcookie(usu string) {
	delete(cookies, usu)
}

func tienescookie(usu string) bool {
	var tienes bool
	tienes = false

	for clave, Cookie := range cookies {
		fmt.Println("key[%s] value[%s]\n", clave, Cookie)
		fmt.Println("USUARIO: " + Cookie.name)
		if Cookie.name == usu {
			tienes = true
		}
	}
	if tienes == true {
		fmt.Println("tienes ya una COOKIE madafaka: " + usu)
	} else {
		fmt.Println("NO tienes una COOKIE madafaka: " + usu)
	}
	return tienes
}

func comprobartime(usu string) bool {
	var nuevaCookie Cookie
	for clave, Cookie := range cookies {
		fmt.Println("key[%s] value[%s]\n", clave, Cookie)
		fmt.Println("USUARIO: " + Cookie.name)
		if Cookie.name == usu {
			//sumamos 5 min al tiempo de la ultimapeti
			tiempocookie := Cookie.ultimapeti.Local().Add(time.Hour*time.Duration(0) +
				time.Minute*time.Duration(1) +
				time.Second*time.Duration(0))

			//cogemos el tiempo actual
			tiempoactu := time.Now()

			//si el tiempo actual esta mas adelantado que la ultima peticion+5min entonces quitale la cookie
			if tiempoactu.After(tiempocookie) {
				fmt.Println("tiempo excedido NO MORE COOKIE FOR YOU: " + usu)
				eliminarcookie(usu)
				return false
			} else {
				fmt.Println("tiempo renovado de COOKIE: " + usu)

				nuevaCookie.name = usu
				nuevaCookie.ultimapeti = time.Now()
				cookies[usu] = nuevaCookie
				return true
			}
		}
	}
	return false
}

/*func checkcookiestime(usu string) bool {
	var pasado bool
	pasado = false
	var actualtime time.Time

	for clave, cookie := range cookies {
		if cookie.name == usu {
			actualtime = time.Now().Minute()
			actualtime.Add(5)
			if cookie.ultimapeti.Minute() < actualtime {
				pasado = true
			}
			break
		}
	}

	return pasado
}*/

/***
CLIENTE
***/

func menuP(usu string) {
	var input int
	n, err := fmt.Scanln(&input)
	if n < 1 || err != nil {
		fmt.Println("invalid input")
		return
	}
	switch input {
	case 1:
		fmt.Println("Opción 1")
		pedircontraseñas(usu)
	case 2:
		fmt.Println("Opción 2")
		recordarContrasena(usu)
	case 3:
		fmt.Println("Opción 3")
		nuevacontraseña(usu)
	case 4:
		fmt.Println("Opción 4")
		cambiarcontraseña(usu)
	case 5:
		fmt.Println("Opción 5")
		eliminarcontraseñas(usu)
	case 6:
		fmt.Println("Opción 6")
		client()
	}
}

func menuPrincipal(usu string) {
	for {
		fmt.Println("-----**** TUS CONTRASEÑAS : " + usu + " ****-----")
		fmt.Println("1.Ver contraseñas")
		fmt.Println("2.Recordar contraseña")
		fmt.Println("3.Nueva contraseña")
		fmt.Println("4.Cambiar contraseña")
		fmt.Println("5.Eliminar contraseña")
		fmt.Println("6.Salir")
		fmt.Println("Elige una opción:")
		menuP(usu)
	}
}

func menuInicio() {
	var input int
	n, err := fmt.Scanln(&input)
	if n < 1 || err != nil {
		fmt.Println("invalid input")
		return
	}
	switch input {
	case 1:
		fmt.Println("Opción 1")
		iniciarSesion()
	case 2:
		fmt.Println("Opción 2")
		registro()
	case 3:
		fmt.Println("Opción 3")
		os.Exit(2)
	}
}

func client() {

	for {
		fmt.Println("-----**** GESTOR DE CONTRASEÑAS ****-----")
		fmt.Println("1.Iniciar Sesion")
		fmt.Println("2.Registrarse")
		fmt.Println("3.Salir")
		fmt.Println("Elige una opción:")
		menuInicio()
	}
}

// gestiona el modo cliente
//func pruebaPeti() {

/* creamos un cliente especial que no comprueba la validez de los certificados
	esto es necesario por que usamos certificados autofirmados (para pruebas)
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}

	// ** ejemplo de registro
	data := url.Values{}             // estructura para contener los valores
	data.Set("cmd", "hola")          // comando (string)
	data.Set("mensaje", "miusuario") // usuario (string)

	r, err := client.PostForm("https://localhost:8081", data) // enviamos por POST
	chk(err)
	//io.Copy(os.Stdout, r.Body) // mostramos el cuerpo de la respuesta (es un reader)
	//fmt.Println()

	// Read body
	b, err := ioutil.ReadAll(r.Body)
	defer r.Body.Close()
	chk(err)

	// Unmarshal
	var msg resp
	err = json.Unmarshal(b, &msg)

	fmt.Println("RESPONSE PRUEBA: " + msg.Msg)

	if msg.Ok == true {
		fmt.Println("Ha funcionado.")
		fmt.Println(msg.Msg)
	}
}*/

func iniciarSesion() {
	fmt.Println("Usuario: ")
	var user string
	//fmt.Scanf("%s", &user)
	_, err := fmt.Scanln(&user)
	chk(err)

	fmt.Println("Password: ")
	bytePassword, err := terminal.ReadPassword(int(syscall.Stdin))
	if err == nil {
		fmt.Println("\nPassword typed: " + string(bytePassword))
	}
	password := string(bytePassword)

	pass := strings.TrimSpace(password)

	//fmt.Printf("Eres: %s con password: %s", user, pass)

	sha_256 := sha256.New()
	sha_256.Write([]byte(pass))
	sha_bytes := sha_256.Sum(nil)
	fmt.Printf("sha256:\t%x\n", sha_bytes)

	pass_sha := base64.StdEncoding.EncodeToString(sha_bytes)

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}

	// ** ejemplo de registro
	data := url.Values{}             // estructura para contener los valores
	data.Set("cmd", "iniciarSesion") // comando (string)
	data.Set("usuario", user)        // usuario (string)
	data.Set("password", pass_sha)   // password (string)

	r, err := client.PostForm("https://localhost:8081", data) // enviamos por POST
	chk(err)
	//io.Copy(os.Stdout, r.Body) // mostramos el cuerpo de la respuesta (es un reader)
	//fmt.Println()

	// Read body
	b, err := ioutil.ReadAll(r.Body)
	defer r.Body.Close()
	chk(err)

	// Unmarshal
	var msg resp
	err = json.Unmarshal(b, &msg)

	//fmt.Println("RESPONSE: " + string(msg.Ok))
	//fmt.Println("RESPONSE2: " + msg.Msg)
	if msg.Ok == true {
		//fmt.Println("Ha funcionado.")
		fmt.Println(msg.Msg)
		var pin string
		_, err := fmt.Scanln(&pin)
		chk(err)

		enviarPin(pin, user)

		//menuPrincipal(user)
	}

	if msg.Ok == false {
		//fmt.Println("ERROR")
		fmt.Println(msg.Msg)
	}
}

func enviarPin(pin string, user string) {

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}

	// ** ejemplo de registro
	data := url.Values{}            // estructura para contener los valores
	data.Set("cmd", "verificarpin") // comando (string)
	data.Set("pin", pin)            // pin (string)
	data.Set("usuario", user)

	r, err := client.PostForm("https://localhost:8081", data) // enviamos por POST
	chk(err)
	//io.Copy(os.Stdout, r.Body) // mostramos el cuerpo de la respuesta (es un reader)
	//fmt.Println()

	// Read body
	b, err := ioutil.ReadAll(r.Body)
	defer r.Body.Close()
	chk(err)

	// Unmarshal
	var msg resp
	err = json.Unmarshal(b, &msg)

	//fmt.Println("RESPONSE: " + string(msg.Ok))
	//fmt.Println("RESPONSE2: " + msg.Msg)
	if msg.Ok == true {
		//fmt.Println("Ha funcionado.")
		fmt.Println(msg.Msg)
		menuPrincipal(user)
	}

	if msg.Ok == false {
		//fmt.Println("ERROR")
		fmt.Println(msg.Msg)
	}
}

func registro() {

	fmt.Println("Usuario: ")
	var user string
	//fmt.Scanf("%s", &user)
	_, err := fmt.Scanln(&user)
	chk(err)

	fmt.Println("Correo: ")
	var corre string
	//fmt.Scanf("%s", &user)
	_, err = fmt.Scanln(&corre)
	chk(err)

	fmt.Println("Password: ")
	bytePassword, err := terminal.ReadPassword(int(syscall.Stdin))
	if err == nil {
		fmt.Println("\nPassword typed: " + string(bytePassword))
	}
	password := string(bytePassword)

	pass := strings.TrimSpace(password)

	sha_256 := sha256.New()
	sha_256.Write([]byte(pass))
	sha_bytes := sha_256.Sum(nil)
	fmt.Printf("sha256:\t%x\n", sha_bytes)

	pass_sha := base64.StdEncoding.EncodeToString(sha_bytes)
	//n := bytes.Index(sha_bytes, []byte{0})
	//pass_sha := string(sha_bytes[:n])
	//pass_sha := convert(sha_bytes[:])
	fmt.Println("EN STRING: " + pass_sha)

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}

	// ** ejemplo de registro
	data := url.Values{}           // estructura para contener los valores
	data.Set("cmd", "registro")    // comando (string)
	data.Set("usuario", user)      // usuario (string)
	data.Set("password", pass_sha) // password (string)
	data.Set("correo", corre)      // correo (string)

	r, err := client.PostForm("https://localhost:8081", data) // enviamos por POST
	chk(err)
	//io.Copy(os.Stdout, r.Body) // mostramos el cuerpo de la respuesta (es un reader)
	//fmt.Println()

	// Read body
	b, err := ioutil.ReadAll(r.Body)
	defer r.Body.Close()
	chk(err)

	// Unmarshal
	var msg resp
	err = json.Unmarshal(b, &msg)

	//fmt.Println("RESPONSE: " + string(msg.Ok))
	//fmt.Println("RESPONSE2: " + msg.Msg)
	if msg.Ok == true {
		//fmt.Println("Ha funcionado.")
		fmt.Println(msg.Msg)
	}

	if msg.Ok == false {
		//fmt.Println("ERROR")
		fmt.Println(msg.Msg)
	}
}

func pedircontraseñas(user string) {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	cliente := &http.Client{Transport: tr}

	// ** ejemplo de registro
	data := url.Values{}                // estructura para contener los valores
	data.Set("cmd", "pedircontraseñas") // comando (string)
	data.Set("usuario", user)           // usuario (string)

	r, err := cliente.PostForm("https://localhost:8081", data) // enviamos por POST
	chk(err)
	//io.Copy(os.Stdout, r.Body) // mostramos el cuerpo de la respuesta (es un reader)
	//fmt.Println()

	// Read body
	b, err := ioutil.ReadAll(r.Body)
	defer r.Body.Close()
	chk(err)

	// Unmarshal
	var msg resp
	err = json.Unmarshal(b, &msg)

	//fmt.Println("RESPONSE: " + string(msg.Ok))
	//fmt.Println("RESPONSE2: " + msg.Msg)
	if msg.Ok == true {
		//fmt.Println("Ha funcionado.")
		fmt.Println(msg.Msg)
		menuPrincipal(user)
	}

	if msg.Ok == false {
		//fmt.Println("ERROR")
		fmt.Println(msg.Msg)
		client()
	}
}

func recordarContrasena(user string) {

	fmt.Println("Introduce el Comentario para busar coincidencias: ")
	var comen string
	//fmt.Scanf("%s", &user)
	_, err := fmt.Scanln(&comen)
	chk(err)

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	cliente := &http.Client{Transport: tr}

	// ** ejemplo de registro
	data := url.Values{}                  // estructura para contener los valores
	data.Set("cmd", "recordarcontrasena") // comando (string)
	data.Set("usuario", user)             // user (string)
	data.Set("comentario", comen)         // comen (string)

	r, err := cliente.PostForm("https://localhost:8081", data) // enviamos por POST
	chk(err)
	//io.Copy(os.Stdout, r.Body) // mostramos el cuerpo de la respuesta (es un reader)
	//fmt.Println()

	// Read body
	b, err := ioutil.ReadAll(r.Body)
	defer r.Body.Close()
	chk(err)

	// Unmarshal
	var msg resp
	err = json.Unmarshal(b, &msg)

	//fmt.Println("RESPONSE: " + string(msg.Ok))
	//fmt.Println("RESPONSE2: " + msg.Msg)
	if msg.Ok == true {
		//fmt.Println("Ha funcionado.")
		fmt.Println(msg.Msg)
		menuPrincipal(user)
	}

	if msg.Ok == false {
		//fmt.Println("ERROR")
		fmt.Println(msg.Msg)
		client()
	}
}

func NewPassword(length int) string {
	return rand_char(length, StdChars)
}

func rand_char(length int, chars []byte) string {
	new_pword := make([]byte, length)
	random_data := make([]byte, length+(length/4)) // storage for random bytes.
	clen := byte(len(chars))
	maxrb := byte(256 - (256 % len(chars)))
	i := 0
	for {
		if _, err := io.ReadFull(rand.Reader, random_data); err != nil {
			panic(err)
		}
		for _, c := range random_data {
			if c >= maxrb {
				continue
			}
			new_pword[i] = chars[c%clen]
			i++
			if i == length {
				return string(new_pword)
			}
		}
	}
	panic("unreachable")
}

func nuevacontraseña(user string) {

	fmt.Println("Comentario: ")
	var comen string
	//fmt.Scanf("%s", &user)
	_, err := fmt.Scanln(&comen)
	chk(err)

	fmt.Println("Usuario: ")
	var us string
	//fmt.Scanf("%s", &user)
	_, err = fmt.Scanln(&us)
	chk(err)

	var contrafinal string
	var input int
	var ok bool
	ok = false
	for ok == false {
		fmt.Println("Quieres una contraseña random o prefieres ponerla tu?")
		fmt.Println("1.Random")
		fmt.Println("2.Yo")
		n, err := fmt.Scanln(&input)
		if n < 1 || err != nil {
			fmt.Println("invalid input")
			//break
		}

		switch input {
		case 1:
			ppass := NewPassword(12)
			contrafinal = strings.TrimSpace(ppass)
			fmt.Println("Tu contraseña autogenerada es: " + contrafinal)
			ok = true
		case 2:
			fmt.Println("Password: ")
			bytePassword, err := terminal.ReadPassword(int(syscall.Stdin))
			if err == nil {
				fmt.Println("\nPassword typed: " + string(bytePassword))
			}
			password := string(bytePassword)
			pass := strings.TrimSpace(password)
			contrafinal = pass
			ok = true
		default:
			fmt.Println("Comando incorrecto")
		}
	}

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	cliente := &http.Client{Transport: tr}

	// ** ejemplo de registro
	data := url.Values{}               // estructura para contener los valores
	data.Set("cmd", "nuevacontraseña") // comando (string)
	data.Set("usuario", user)          // usuario (string)
	data.Set("us", us)                 // usuario del sitio (string)
	data.Set("pass", contrafinal)      // password del sitio (string)
	data.Set("comentario", comen)      // comentario del sitio (string)

	r, err := cliente.PostForm("https://localhost:8081", data) // enviamos por POST
	chk(err)
	//io.Copy(os.Stdout, r.Body) // mostramos el cuerpo de la respuesta (es un reader)
	//fmt.Println()

	// Read body
	b, err := ioutil.ReadAll(r.Body)
	defer r.Body.Close()
	chk(err)

	// Unmarshal
	var msg resp
	err = json.Unmarshal(b, &msg)

	//fmt.Println("RESPONSE: " + string(msg.Ok))
	//fmt.Println("RESPONSE2: " + msg.Msg)
	if msg.Ok == true {
		//fmt.Println("Ha funcionado.")
		fmt.Println(msg.Msg)
		menuPrincipal(user)
	}

	if msg.Ok == false {
		//fmt.Println("ERROR")
		fmt.Println(msg.Msg)
		client()
	}
}

func eliminarcontraseñas(user string) {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	cliente := &http.Client{Transport: tr}

	fmt.Println("Comentario: ")
	var comen string
	//fmt.Scanf("%s", &user)
	_, err := fmt.Scanln(&comen)
	chk(err)

	// ** ejemplo de registro
	data := url.Values{}                   // estructura para contener los valores
	data.Set("cmd", "eliminarcontraseñas") // comando (string)
	data.Set("usuario", user)              // usuario (string)
	data.Set("comentario", comen)          // comentario del sitio (string)

	r, err := cliente.PostForm("https://localhost:8081", data) // enviamos por POST
	chk(err)
	//io.Copy(os.Stdout, r.Body) // mostramos el cuerpo de la respuesta (es un reader)
	//fmt.Println()

	// Read body
	b, err := ioutil.ReadAll(r.Body)
	defer r.Body.Close()
	chk(err)

	// Unmarshal
	var msg resp
	err = json.Unmarshal(b, &msg)

	//fmt.Println("RESPONSE: " + string(msg.Ok))
	//fmt.Println("RESPONSE2: " + msg.Msg)
	if msg.Ok == true {
		//fmt.Println("Ha funcionado.")
		fmt.Println(msg.Msg)
		menuPrincipal(user)
	}

	if msg.Ok == false {
		//fmt.Println("ERROR")
		fmt.Println(msg.Msg)
		client()
	}
}

func cambiarcontraseña(user string) {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	cliente := &http.Client{Transport: tr}

	fmt.Println("Sitio del que quieres cambiar los datos?(comentrio): ")
	var comen string
	//fmt.Scanf("%s", &user)
	_, err := fmt.Scanln(&comen)
	chk(err)

	fmt.Println("Nuevo Usuario: ")
	var us string
	//fmt.Scanf("%s", &user)
	_, err = fmt.Scanln(&us)
	chk(err)

	fmt.Println("Nueva Password: ")
	bytePassword, err := terminal.ReadPassword(int(syscall.Stdin))
	if err == nil {
		fmt.Println("\nPassword typed: " + string(bytePassword))
	}
	password := string(bytePassword)

	pass := strings.TrimSpace(password)

	// ** ejemplo de registro
	data := url.Values{}                 // estructura para contener los valores
	data.Set("cmd", "cambiarcontraseña") // comando (string)
	data.Set("usuario", user)            // usuario (string)
	data.Set("us", us)                   // usuario del sitio (string)
	data.Set("pass", pass)               // password del sitio (string)
	data.Set("comentario", comen)        // comentario del sitio (string)

	r, err := cliente.PostForm("https://localhost:8081", data) // enviamos por POST
	chk(err)
	//io.Copy(os.Stdout, r.Body) // mostramos el cuerpo de la respuesta (es un reader)
	//fmt.Println()

	// Read body
	b, err := ioutil.ReadAll(r.Body)
	defer r.Body.Close()
	chk(err)

	// Unmarshal
	var msg resp
	err = json.Unmarshal(b, &msg)

	//fmt.Println("RESPONSE: " + string(msg.Ok))
	//fmt.Println("RESPONSE2: " + msg.Msg)
	if msg.Ok == true {
		//fmt.Println("Ha funcionado.")
		fmt.Println(msg.Msg)
		menuPrincipal(user)
	}

	if msg.Ok == false {
		//fmt.Println("ERROR")
		fmt.Println(msg.Msg)
		client()
	}
}
