console.log("Client-side code running");

document.addEventListener("DOMContentLoaded", function () {
  setInterval(function () {
    var currentTime = new Date();
    var hours = currentTime.getHours().toString().padStart(2, "0");
    var minutes = currentTime.getMinutes().toString().padStart(2, "0");
    var seconds = currentTime.getSeconds().toString().padStart(2, "0");
    document.getElementById("currentTime").innerText =
      hours + ":" + minutes + ":" + seconds;
  }, 1000);
});

function loadDataBase() {
  fetch("/db", { method: "GET" })
    .then((response) => response.json())
    .then((data) => {
      document.getElementById("sensorValue").innerHTML = data.rawValue;
    });
}

const button = document.getElementById("myButton");
button.addEventListener("click", function (e) {
  console.log("myButton button was clicked");
  fetch("/db", { method: "GET" })
    .then(function (response) {
      if (response.ok) return response.json();
      throw new Error("Request failed.");
    })
    .then(function (data) {
      document.getElementById("counter").innerHTML = ` Data: ${JSON.stringify(
        data
      )}`;
    })
    .catch(function (error) {
      console.log(error);
    });
});

const inputTextField = document.getElementById("messageInput");

const sendButton = document.getElementById("sendButton");
console.log(sendButton);
sendButton.addEventListener("click", function (e) {
  console.log("sendButton button was clicked");

  console.log("this is a test");
  fetch("/sendMessage", {
    method: "POST",
    body: JSON.stringify({
      text: inputTextField.innerText,
    }),
    headers: {
      "Content-Type": "application/json",
    },
  })
    .then(function (response) {
      if (response.ok) {
        console.log("click was recorded");
        return;
      }
      throw new Error("Request failed.");
    })
    .catch(function (error) {
      console.log(error);
    });
});
