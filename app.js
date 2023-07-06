const express = require("express");
const sql = require("mssql");
const Client = require("azure-iothub").Client;
const Message = require("azure-iot-common").Message;

const app = express();
const port = process.env.PORT || 3000;
app.use(express.json());

const config = {
  user: "loki",
  password: "SFQD2rmefhssmz",
  server: "pleant-loki.database.windows.net",
  port: 1433,
  database: "plaent-loki-database",
  options: {
    encrypt: true,
  },
};

app.use(express.static("public"));

app.listen(port, () => {
  console.log(`Example app listening at http://localhost:${port}`);
});

app.get("/", function (req, res) {
  res.sendFile(__dirname + "/index.html");
});

app.get("/db", (req, res) => {
  sql.connect(config, function (err) {
    if (err) console.log(err);

    var request = new sql.Request();
    request.query(
      "SELECT TOP 1 rawValue, moisturePercentage FROM [dbo].[new-table] ORDER BY EventProcessedUtcTime DESC",
      function (err, recordset) {
        if (err) console.log(err);
        res.status(200).json(recordset.recordset[0]); // return only the first record
      }
    );
  });
});

app.post("/sendMessage", (req, res) => {
  // "HostName=plaent-loki.azure-devices.net;DeviceId=plaent-loki;SharedAccessKey=d8C84CS8bL+iCYJfLQNBKQ14WvinRXGDF6740objJcE=";
  console.log(req.body);
  var connectionString =
    "HostName=plaent-loki.azure-devices.net;SharedAccessKeyName=iothubowner;SharedAccessKey=sJ16WxWzBOnTFyka3ng49GvRYm5z8JYr0mwV/oh774U=;DeviceId=plaent-loki";
  var targetDevice = "plaent-loki";

  var client = Client.fromConnectionString(connectionString);

  client.open(function (err) {
    if (err) {
      console.error("Could not connect: " + err.message);
    } else {
      console.log("Client connected");
      var data = JSON.stringify({
        state: req.body.message,
        name: "sensor",
      });
      var message = new Message(data);
      console.log("Sending message: " + message.getData());
      client.send(targetDevice, message, printResultFor("send"));
    }
  });

  function printResultFor(op) {
    return function printResult(err, resLokal) {
      if (err) {
        console.log(op + " error: " + err.toString());
      } else {
        console.log(op + " status: " + resLokal.constructor.name);
        res.status(201).json(op + " status: " + resLokal.constructor.name);
      }
    };
  }
});
