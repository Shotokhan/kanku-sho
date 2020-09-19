# json schema, with example values
"""
Payload data in JSON is base64 encoding of gzip of hex data, whereas in database it is just
the gzip of hex data.
{
   "timestamp":"10_09_2020_18:34",
   "user":"root",
   "host":"10.10.17.1",
   "flag_regex":"flg\\{[A-Za-z0-9]{25}\\}",
   "interface":"any",
   "streams":{
      "0":{
         "type":"regex in",
         "flag_sn":"0",
         "number":"0",
         "protocol":"http",
         "local_port":"8000",
         "remote_port":"41198",
         "remote_ip":"127.0.0.1",
         "payloads":[
            {
               "http":{
                  "method":"POST",
                  "URI":"/",
                  "parameters":{
                     "flag":"flg{r99fg2EJCrYUtZIT8nQrt0xTH}"
                  },
                  "status_code":""
               },
               "type":"request",
               "data":"H4sIAMapXF8C/wMAAAAAAAAAAAA=",
               "sequence_number":0
            },
         ]
      },
   }
}
"""
