
function check() {
    if (document.getElementById('txtNewPassword').value == document.getElementById('txtConfirmPassword').value) {
        document.getElementById('message').style.color = 'green';
        document.getElementById('message').innerHTML = 'matching';
        bt.disabled = false;
    } else {
        document.getElementById('message').style.color = 'red';
        document.getElementById('message').innerHTML = 'not matching';
        document.getElementById('message').style.background = 'rgba(255, 255, 255, 0.42)';


    }
}
function validatePassword() {
    var InputValue = $("#txtNewPassword").val();
    var regex = new RegExp("^(?=.*[a-z])(?=.*[A-Z])(?=.*[0-9])(?=.*[!@#\$%\^&\*])(?=.{6,})");
    $("#passwordText").text(`Password value:- ${InputValue}`);
    if (!regex.test(InputValue)) {
        $("#error").text("*Password must contains minimum 8 characters including 1 uppercase 1 lowercase 1 number 1 special character*");
    }
    else {
        $("#error").text("");
        bt.disabled = false
    }
}

$("#sugmail").click(function () {
    var value = $(this).html();
    var input = $('#user_mail');
    input.val(value);
});



const container = document.querySelector(".container");

const main = document.querySelector(".main__content");




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


const pass_fields = document.querySelector(".confirmpass");
const showBtns = document.querySelector(".confirmpasswordshow");
showBtn.addEventListener("click", function () {
    if (pass_fields.type === "password") {
        pass_fields.type = "text";
        showBtns.textContent = "HIDE";
        showBtns.style.color = "#D052F6";
    } else {
        pass_fields.type = "password";
        showBtns.textContent = "SHOW";
        showBtns.style.color = "#222";
    }
});
