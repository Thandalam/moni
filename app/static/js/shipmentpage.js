const container = document.querySelector(".container");
const nav = document.querySelector(".sidebar");
const main = document.querySelector(".main__content");

container.addEventListener("click", (e) => {
    const toggleBtn = document.querySelector(".nav__toggle--input");
    if (e.target.closest(".sidebar") || e.target.contains(toggleBtn)) {
        return;
    }
    toggleBtn.checked = false;
});


function blockSpecialChar(e) {
    var k;
    document.all ? k = e.keyCode : k = e.which;
    return ((k > 64 && k < 91) || (k > 96 && k < 123) || k == 8 || k == 32 || (k >= 48 && k <= 57));
  }
