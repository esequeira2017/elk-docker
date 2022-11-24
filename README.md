# docker-elastic
[Elastic stack](https://www.elastic.co/es/) sobre [Docker](https://www.docker.com/).

## Arrancar el stack Elastic

Para arrancar los contenedores del stack Elastic, ejecutar el siguiente comando:
```bash
$ docker-compose up -d
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