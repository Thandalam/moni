
const container = document.querySelector(".container");
// const nav = document.querySelector(".sidebar");
const main = document.querySelector(".main__content");




let refbtn = document.getElementById("refreshbtn")

let submitBTN = document.getElementById("submitbtn")

var code;
function createCaptcha() {
    document.getElementById('captcha').innerHTML = "";
    var charsArray =
        "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ@!#";
    var lengthOtp = 5;
    var captcha = [];
    for (var i = 0; i < lengthOtp; i++) {
        var index = Math.floor(Math.random() * charsArray.length + 1);
        if (captcha.indexOf(charsArray[index]) == -1)
            captcha.push(charsArray[index]);
        else i--;
    }
    var canv = document.createElement("canvas");
    canv.id = "captcha";
    canv.width = 100;
    canv.height = 50;
    var ctx = canv.getContext("2d");
    ctx.font = "25px Georgia";
    ctx.strokeText(captcha.join(""), 0, 30);

    code = captcha.join("");
    document.getElementById("captcha").appendChild(canv);
}
var capt = false
var validate_login = document.getElementById("validate_login")
validate_login.disabled = true;
function validateCaptcha() {
    var capt = document.getElementById("cpatchaTextBox").value;
    if (capt == code) {
        capt = true;
        document.getElementById("captchaError").innerHTML = '';
        validate_login.disabled = false;
    }
    else {
        capt = false;
        document.getElementById("captchaError").innerHTML = 'Invalid captcha';

    }

}



const pass_field = document.querySelector(".pass");
const showBtn = document.querySelector(".show");
showBtn.addEventListener("click", function () {
    if (pass_field.type === "password") {
        pass_field.type = "text";
        showBtn.textContent = "HIDE";
        showBtn.style.color = "#D052F6";
    } else {
        pass_field.type = "password";
        showBtn.textContent = "SHOW";
        showBtn.style.color = "#222";
    }
});
