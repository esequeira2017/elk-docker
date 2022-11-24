# Instalacion y configuracion de ELK


**¿Què es ELK?**

Es un conjunto de herramientas de gran potencial de código abierto que se combinan para crear una herramienta de administración de registros permitiendo la monitorización, consolidación y análisis de logs generados en múltiples servidores, estas herramientas son:ElasticSearch, Logstash y Kibana.

También pueden ser utilizadas como herramientas independientes, pero la unión de todas ellas hace una combinación perfecta para la gestión de registros como ya hemos mencionado.

ELK es un stack compuesta por tres pilares fundamentales: Elasticsearch, Logstash y Kibana

![como-funciona-elk.jpg](https://dev.azure.com/GDHIR/7c8368a7-a22b-448d-a187-c9e54a3901c6/_apis/wiki/wikis/88510f18-4d04-43b6-a74e-7885a496ba16/pages/500/comments/attachments/5b731582-066b-43ff-80df-9919e56570cf) 

# docker-elastic
[Elastic stack](https://www.elastic.co/es/) sobre [Docker](https://www.docker.com/).

## Arrancar el stack Elastic

Para arrancar los contenedores del stack Elastic, ejecutar el siguiente comando:
```bash
$ docker-compose up -d
```

Aplicar fix volume:

```bash
$ sudo chown -R 1000:1000 elasticsearch/
```

Para verificar que los tres contenedores del stack se están ejecutando correctamente, ejecutar el siguiente comando:

```bash
$ docker-compose ps
NAME                COMMAND                  SERVICE             STATUS              PORTS
elasticsearch       "/bin/tini -- /usr/l…"   elasticsearch       running             0.0.0.0:9200->9200/tcp, 0.0.0.0:9300->9300/tcp
kibana              "/bin/tini -- /usr/l…"   kibana              running             0.0.0.0:5601->5601/tcp
logstash            "/usr/local/bin/dock…"   logstash            running             0.0.0.0:5000->5000/tcp, 0.0.0.0:5044->5044/tcp, 0.0.0.0:9600->9600/tcp
```

## Visualizar los logs

Para visualizar los logs, ejecutar el siguiente comando:

```bash
$ docker-compose logs -f
```

## Verificar el funcionamiento de Elasticsearch 

Acceder con un navegador a http://localhost:9200 para verificar que Elasticsearch ha arrancado correctamente.

## Configuración del pipeline de Logstash

A continuación, se muestra el fichero [logstash/pipeline/logstash.conf](https://github.com/aprenderdevops/docker-elastic/blob/main/logstash/pipeline/logstash.conf), que contiene la configuración del pipeline de Logstash:

```
input {
  heartbeat {
    message => "ok"
    interval => 5
    type => "heartbeat"
  }
}

output {
  if [type] == "heartbeat" {
    elasticsearch {
      hosts => "elasticsearch:9200"
      index => "heartbeat"
    }
  }
  stdout {
    codec => "rubydebug"
  }
}
```

Con esta configuración se genera cada 5 segundos un evento mediante el [plugin heartbeat](https://www.elastic.co/guide/en/logstash/current/plugins-inputs-heartbeat.html).

No se ha incluido ningún [filter](https://www.elastic.co/guide/en/logstash/current/filter-plugins.html), por lo que, con los eventos generados no se va a realizar ningún tipo de procesamiento o transformación.

En la sección output se configura la salida de los eventos para su envío al índice heartbeat de Elasticsearch cuando estos hayan sido generados por el plugin heartbeat. También se envían todos los eventos por la salida estándar mediante el [plugin stdout](https://www.elastic.co/guide/en/logstash/current/plugins-outputs-stdout.html) utilizando el formato definido por el [códec rubydebug](https://www.elastic.co/guide/en/logstash/current/plugins-codecs-rubydebug.html).

## Comprobar el funcionamiento del pipeline de Logstash

Para comprobar que los eventos de tipo heartbeat se están generando cada 5 segundos y se están enviando a la salida estándar, se puede ejecutar el siguiente comando:

```bash
$ docker logs logstash -n21 -f
{
          "host" => "18ff4068ddbb",
      "@version" => "1",
    "@timestamp" => 2021-11-11T00:10:11.934Z,
          "type" => "heartbeat",
       "message" => "ok"
}
{
          "host" => "18ff4068ddbb",
      "@version" => "1",
    "@timestamp" => 2021-11-11T00:10:16.935Z,
          "type" => "heartbeat",
       "message" => "ok"
}
{
          "host" => "18ff4068ddbb",
      "@version" => "1",
    "@timestamp" => 2021-11-11T00:10:21.935Z,
          "type" => "heartbeat",
       "message" => "ok"
}
```

La salida de este comando deberá mostrar cada 5 segundos un nuevo evento de tipo heartbeat.

Para comprobar que los eventos también se están enviado a Elasticsearch, se puede ejecutar el siguiente comando:

```bash
$ curl -XGET "http://localhost:9200/heartbeat/_search?pretty=true" -H 'Content-Type: application/json' -d'{"size": 1}'
{
  "took" : 521,
  "timed_out" : false,
  "_shards" : {
    "total" : 1,
    "successful" : 1,
    "skipped" : 0,
    "failed" : 0
  },
  "hits" : {
    "total" : {
      "value" : 3853,
      "relation" : "eq"
    },
    "max_score" : 1.0,
    "hits" : [
      {
        "_index" : "heartbeat",
        "_type" : "_doc",
        "_id" : "m9El_HwB8PSqowAaYELN",
        "_score" : 1.0,
        "_source" : {
          "type" : "heartbeat",
          "message" : "ok",
          "host" : "e66d07ee3402",
          "@timestamp" : "2021-11-07T20:44:39.599Z",
          "@version" : "1"
        }
      }
    ]
  }
}
```

La salida de este comando deberá mostrar el primer evento de tipo heartbeat generado.

## Acceder a Kibana

Para entrar en Kibana abrir un navegador y acceder a [http://localhost:5601](http://localhost:5601/).

---

Tags: devops, docker, elastic

# Instalar Filebeat en una instancia VM GCP


```
$ curl -L -O https://artifacts.elastic.co/downloads/beats/filebeat/filebeat-7.17.7-amd64.deb
$ sudo dpkg -i filebeat-7.17.7-amd64.deb
```
Editamos el archivo de configuracion:
```
$ vi /etc/filebeat/filebeat.yml

 filebeat.inputs:
   tags: ["docker"]
   id: my-filestream-id
   paths:
     # - /var/log/nginx/access.log
     - '/var/lib/docker/containers/*/*-json.log'

 setup.kibana:
   host: "10.128.0.5:5601"

 output.elasticsearch:
   hosts: ["10.128.0.5:9200"]
```
Hacemos un test:

`$ filebeat setup`

Añadimos un indice manualmente:

```
$ filebeat setup --index-management -E output.logstash.enabled=false -E 'output.elasticsearch.hosts=["10.128.0.5:9200"]'
```

Inicializar el indice llamado filebeat-7.17.7-2022.11.07-000001 en 0, lo hacemos desde Kibana, 
```
PUT /filebeat-7.17.7-2022.11.07-000001/_settings
{
    "index" : {
        "number_of_replicas" : 0
    }
}
```

Configurar una vista en Kibana:

Primero creamos el index:

 **Management ** -->  **Kibana ** -->  **Index Patterns **

Vamos a las siguientes opciones:
 **Observability** -->  **Logs** --> **Stream** --> **Setting** --> **Indices** --> **filebeat-***


## **Bare-Metal:**

**1: Instalar y configurar Elasticsearch**


```
$ wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | sudo apt-key add -
$ echo "deb https://artifacts.elastic.co/packages/6.x/apt stable main" | sudo tee -a /etc/apt/sources.list.d/elastic-6.x.list
$ sudo apt update
$ sudo apt install elasticsearch
$ sudo vi /etc/elasticsearch/elasticsearch.yml
    . . .
    network.host: localhost
    . . .

$sudo systemctl start elasticsearch
$sudo systemctl enable elasticsearch
$curl -X GET "localhost:9200"
```


**2: Instalar y configurar el panel de Kibana**


```
$ sudo apt install kibana
$ sudo systemctl enable kibana
$ sudo vi /etc/elasticsearch/elasticsearch.yml
    . . .
    server.host: 0.0.0.0
    . . .
$ sudo systemctl start kibana

$ echo "kibanaadmin:`openssl passwd -apr1`" | sudo tee -a /etc/nginx/htpasswd.users
$ sudo apt install nginx
$ sudo nano /etc/nginx/sites-available/example.com

    server {
        listen 80;

        server_name example.com;

        auth_basic "Restricted Access";
        auth_basic_user_file /etc/nginx/htpasswd.users;

        location / {
            proxy_pass http://localhost:5601;
            proxy_http_version 1.1;
            proxy_set_header Upgrade $http_upgrade;
            proxy_set_header Connection 'upgrade';
            proxy_set_header Host $host;
            proxy_cache_bypass $http_upgrade;
        }
    }

$ sudo ln -s /etc/nginx/sites-available/example.com /etc/nginx/sites-enabled/example.com
$ sudo nginx -t
$ sudo systemctl restart nginx

 http://your_server_ip/status
```

**3: Instalar y configurar Logstash**


```
$ sudo apt install logstash
$ sudo vi /etc/logstash/conf.d/02-beats-input.conf

    input {
      beats {
        port => 5044
      }
    }

$ sudo vi /etc/logstash/conf.d/10-syslog-filter.conf

    filter {
      if [fileset][module] == "system" {
        if [fileset][name] == "auth" {
          grok {
            match => { "message" => ["%{SYSLOGTIMESTAMP:[system][auth][timestamp]} %{SYSLOGHOST:[system][auth][hostname]} sshd(?:\[%{POSINT:[system][auth][pid]}\])?: %{DATA:[system][auth][ssh][event]} %{DATA:[system][auth][ssh][method]} for (invalid user )?%{DATA:[system][auth][user]} from %{IPORHOST:[system][auth][ssh][ip]} port %{NUMBER:[system][auth][ssh][port]} ssh2(: %{GREEDYDATA:[system][auth][ssh][signature]})?",
                      "%{SYSLOGTIMESTAMP:[system][auth][timestamp]} %{SYSLOGHOST:[system][auth][hostname]} sshd(?:\[%{POSINT:[system][auth][pid]}\])?: %{DATA:[system][auth][ssh][event]} user %{DATA:[system][auth][user]} from %{IPORHOST:[system][auth][ssh][ip]}",
                      "%{SYSLOGTIMESTAMP:[system][auth][timestamp]} %{SYSLOGHOST:[system][auth][hostname]} sshd(?:\[%{POSINT:[system][auth][pid]}\])?: Did not receive identification string from %{IPORHOST:[system][auth][ssh][dropped_ip]}",
                      "%{SYSLOGTIMESTAMP:[system][auth][timestamp]} %{SYSLOGHOST:[system][auth][hostname]} sudo(?:\[%{POSINT:[system][auth][pid]}\])?: \s*%{DATA:[system][auth][user]} :( %{DATA:[system][auth][sudo][error]} ;)? TTY=%{DATA:[system][auth][sudo][tty]} ; PWD=%{DATA:[system][auth][sudo][pwd]} ; USER=%{DATA:[system][auth][sudo][user]} ; COMMAND=%{GREEDYDATA:[system][auth][sudo][command]}",
                      "%{SYSLOGTIMESTAMP:[system][auth][timestamp]} %{SYSLOGHOST:[system][auth][hostname]} groupadd(?:\[%{POSINT:[system][auth][pid]}\])?: new group: name=%{DATA:system.auth.groupadd.name}, GID=%{NUMBER:system.auth.groupadd.gid}",
                      "%{SYSLOGTIMESTAMP:[system][auth][timestamp]} %{SYSLOGHOST:[system][auth][hostname]} useradd(?:\[%{POSINT:[system][auth][pid]}\])?: new user: name=%{DATA:[system][auth][user][add][name]}, UID=%{NUMBER:[system][auth][user][add][uid]}, GID=%{NUMBER:[system][auth][user][add][gid]}, home=%{DATA:[system][auth][user][add][home]}, shell=%{DATA:[system][auth][user][add][shell]}$",
                      "%{SYSLOGTIMESTAMP:[system][auth][timestamp]} %{SYSLOGHOST:[system][auth][hostname]} %{DATA:[system][auth][program]}(?:\[%{POSINT:[system][auth][pid]}\])?: %{GREEDYMULTILINE:[system][auth][message]}"] }
            pattern_definitions => {
              "GREEDYMULTILINE"=> "(.|\n)*"
            }
            remove_field => "message"
          }
          date {
            match => [ "[system][auth][timestamp]", "MMM  d HH:mm:ss", "MMM dd HH:mm:ss" ]
          }
          geoip {
            source => "[system][auth][ssh][ip]"
            target => "[system][auth][ssh][geoip]"
          }
        }
        else if [fileset][name] == "syslog" {
          grok {
            match => { "message" => ["%{SYSLOGTIMESTAMP:[system][syslog][timestamp]} %{SYSLOGHOST:[system][syslog][hostname]} %{DATA:[system][syslog][program]}(?:\[%{POSINT:[system][syslog][pid]}\])?: %{GREEDYMULTILINE:[system][syslog][message]}"] }
            pattern_definitions => { "GREEDYMULTILINE" => "(.|\n)*" }
            remove_field => "message"
          }
          date {
            match => [ "[system][syslog][timestamp]", "MMM  d HH:mm:ss", "MMM dd HH:mm:ss" ]
          }
        }
      }
    }
```


```
$ sudo vi /etc/logstash/conf.d/30-elasticsearch-output.conf

    output {
      elasticsearch {
        hosts => ["localhost:9200"]
        manage_template => false
        index => "%{[@metadata][beat]}-%{[@metadata][version]}-%{+YYYY.MM.dd}"
      }
    }

$ sudo -u logstash /usr/share/logstash/bin/logstash --path.settings /etc/logstash -t
$ sudo systemctl start logstash
$ sudo systemctl enable logstash
```

**4: Instalar y configurar Filebeat**


```
$ sudo apt install filebeat

$ sudo vi /etc/filebeat/filebeat.yml

    ...
    #output.elasticsearch:
      # Array of hosts to connect to.
      #hosts: ["localhost:9200"]
    ...

    output.logstash:
      # The Logstash hosts
      hosts: ["localhost:5044"]

$ sudo filebeat modules enable system
$ sudo filebeat modules list
$ sudo filebeat setup --template -E output.logstash.enabled=false -E 'output.elasticsearch.hosts=["localhost:9200"]'
$ sudo filebeat setup -e -E output.logstash.enabled=false -E output.elasticsearch.hosts=['localhost:9200'] -E setup.kibana.host=localhost:5601
$ sudo systemctl start filebeat
$ sudo systemctl enable filebeat
$ curl -XGET 'http://localhost:9200/filebeat-*/_search?pretty'
```


