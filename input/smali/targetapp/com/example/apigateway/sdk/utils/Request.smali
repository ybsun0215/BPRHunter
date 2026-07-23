.class public Lcom/example/apigateway/sdk/utils/Request;
.super Ljava/lang/Object;
.source "Request.java"


# static fields
.field private static final PATTERN:Ljava/util/regex/Pattern;


# instance fields
.field private body:Ljava/lang/String;

.field private headers:Ljava/util/Map;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/Map<",
            "Ljava/lang/String;",
            "Ljava/lang/String;",
            ">;"
        }
    .end annotation
.end field

.field private key:Ljava/lang/String;

.field private method:Ljava/lang/String;

.field private queryString:Ljava/util/Map;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/Map<",
            "Ljava/lang/String;",
            "Ljava/util/List<",
            "Ljava/lang/String;",
            ">;>;"
        }
    .end annotation
.end field

.field private secret:Ljava/lang/String;

.field private url:Ljava/lang/String;


# direct methods
.method static constructor <clinit>()V
    .registers 1

    const-string v0, "^(?i)(post|put|patch|delete|get|options|head)$"

    invoke-static {v0}, Ljava/util/regex/Pattern;->compile(Ljava/lang/String;)Ljava/util/regex/Pattern;

    move-result-object v0

    sput-object v0, Lcom/example/apigateway/sdk/utils/Request;->PATTERN:Ljava/util/regex/Pattern;

    return-void
.end method

.method public constructor <init>()V
    .registers 2

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    const/4 v0, 0x0

    iput-object v0, p0, Lcom/example/apigateway/sdk/utils/Request;->key:Ljava/lang/String;

    iput-object v0, p0, Lcom/example/apigateway/sdk/utils/Request;->secret:Ljava/lang/String;

    iput-object v0, p0, Lcom/example/apigateway/sdk/utils/Request;->method:Ljava/lang/String;

    iput-object v0, p0, Lcom/example/apigateway/sdk/utils/Request;->url:Ljava/lang/String;

    iput-object v0, p0, Lcom/example/apigateway/sdk/utils/Request;->body:Ljava/lang/String;

    new-instance v0, Ljava/util/Hashtable;

    invoke-direct {v0}, Ljava/util/Hashtable;-><init>()V

    iput-object v0, p0, Lcom/example/apigateway/sdk/utils/Request;->headers:Ljava/util/Map;

    new-instance v0, Ljava/util/Hashtable;

    invoke-direct {v0}, Ljava/util/Hashtable;-><init>()V

    iput-object v0, p0, Lcom/example/apigateway/sdk/utils/Request;->queryString:Ljava/util/Map;

    return-void
.end method


# virtual methods
.method public addHeader(Ljava/lang/String;Ljava/lang/String;)V
    .registers 4

    if-eqz p1, :cond_e

    invoke-virtual {p1}, Ljava/lang/String;->trim()Ljava/lang/String;

    move-result-object v0

    invoke-virtual {v0}, Ljava/lang/String;->isEmpty()Z

    move-result v0

    if-eqz v0, :cond_d

    goto :goto_e

    :cond_d
    iget-object v0, p0, Lcom/example/apigateway/sdk/utils/Request;->headers:Ljava/util/Map;

    invoke-interface {v0, p1, p2}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    :cond_e
    :goto_e
    return-void
.end method

.method public getBody()Ljava/lang/String;
    .registers 2

    iget-object v0, p0, Lcom/example/apigateway/sdk/utils/Request;->body:Ljava/lang/String;

    return-object v0
.end method

.method public getHeaders()Ljava/util/Map;
    .registers 2
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Ljava/util/Map<",
            "Ljava/lang/String;",
            "Ljava/lang/String;",
            ">;"
        }
    .end annotation

    iget-object v0, p0, Lcom/example/apigateway/sdk/utils/Request;->headers:Ljava/util/Map;

    return-object v0
.end method

.method public getHost()Ljava/lang/String;
    .registers 4

    iget-object v0, p0, Lcom/example/apigateway/sdk/utils/Request;->url:Ljava/lang/String;

    const-string v1, "://"

    invoke-virtual {v0, v1}, Ljava/lang/String;->indexOf(Ljava/lang/String;)I

    move-result v1

    if-ltz v1, :cond_10

    add-int/lit8 v1, v1, 0x3

    invoke-virtual {v0, v1}, Ljava/lang/String;->substring(I)Ljava/lang/String;

    move-result-object v0

    :cond_10
    const/16 v1, 0x2f

    invoke-virtual {v0, v1}, Ljava/lang/String;->indexOf(I)I

    move-result v1

    if-ltz v1, :cond_1d

    const/4 v2, 0x0

    invoke-virtual {v0, v2, v1}, Ljava/lang/String;->substring(II)Ljava/lang/String;

    move-result-object v0

    :cond_1d
    return-object v0
.end method

.method public getKey()Ljava/lang/String;
    .registers 2

    iget-object v0, p0, Lcom/example/apigateway/sdk/utils/Request;->key:Ljava/lang/String;

    return-object v0
.end method

.method public getMethod()Lcom/example/sdk/http/HttpMethodName;
    .registers 3

    iget-object v0, p0, Lcom/example/apigateway/sdk/utils/Request;->method:Ljava/lang/String;

    invoke-static {}, Ljava/util/Locale;->getDefault()Ljava/util/Locale;

    move-result-object v1

    invoke-virtual {v0, v1}, Ljava/lang/String;->toUpperCase(Ljava/util/Locale;)Ljava/lang/String;

    move-result-object v0

    invoke-static {v0}, Lcom/example/sdk/http/HttpMethodName;->valueOf(Ljava/lang/String;)Lcom/example/sdk/http/HttpMethodName;

    move-result-object v0

    return-object v0
.end method

.method public getPath()Ljava/lang/String;
    .registers 3

    iget-object v0, p0, Lcom/example/apigateway/sdk/utils/Request;->url:Ljava/lang/String;

    const-string v1, "://"

    invoke-virtual {v0, v1}, Ljava/lang/String;->indexOf(Ljava/lang/String;)I

    move-result v1

    if-ltz v1, :cond_10

    add-int/lit8 v1, v1, 0x3

    invoke-virtual {v0, v1}, Ljava/lang/String;->substring(I)Ljava/lang/String;

    move-result-object v0

    :cond_10
    const/16 v1, 0x2f

    invoke-virtual {v0, v1}, Ljava/lang/String;->indexOf(I)I

    move-result v1

    if-ltz v1, :cond_1d

    invoke-virtual {v0, v1}, Ljava/lang/String;->substring(I)Ljava/lang/String;

    move-result-object v0

    return-object v0

    :cond_1d
    const-string v0, "/"

    return-object v0
.end method

.method public getQueryStringParams()Ljava/util/Map;
    .registers 2
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Ljava/util/Map<",
            "Ljava/lang/String;",
            "Ljava/util/List<",
            "Ljava/lang/String;",
            ">;>;"
        }
    .end annotation

    iget-object v0, p0, Lcom/example/apigateway/sdk/utils/Request;->queryString:Ljava/util/Map;

    return-object v0
.end method

.method public getSecrect()Ljava/lang/String;
    .registers 2

    iget-object v0, p0, Lcom/example/apigateway/sdk/utils/Request;->secret:Ljava/lang/String;

    return-object v0
.end method

.method public setAppKey(Ljava/lang/String;)V
    .registers 1

    iput-object p1, p0, Lcom/example/apigateway/sdk/utils/Request;->key:Ljava/lang/String;

    return-void
.end method

.method public setAppSecrect(Ljava/lang/String;)V
    .registers 1

    iput-object p1, p0, Lcom/example/apigateway/sdk/utils/Request;->secret:Ljava/lang/String;

    return-void
.end method

.method public setBody(Ljava/lang/String;)V
    .registers 1

    iput-object p1, p0, Lcom/example/apigateway/sdk/utils/Request;->body:Ljava/lang/String;

    return-void
.end method

.method public setMethod(Ljava/lang/String;)V
    .registers 1

    iput-object p1, p0, Lcom/example/apigateway/sdk/utils/Request;->method:Ljava/lang/String;

    return-void
.end method

.method public setUrl(Ljava/lang/String;)V
    .registers 8

    const/16 v0, 0x3f

    invoke-virtual {p1, v0}, Ljava/lang/String;->indexOf(I)I

    move-result v0

    iput-object p1, p0, Lcom/example/apigateway/sdk/utils/Request;->url:Ljava/lang/String;

    if-gez v0, :cond_b

    return-void

    :cond_b
    add-int/lit8 v1, v0, 0x1

    invoke-virtual {p1}, Ljava/lang/String;->length()I

    move-result v2

    invoke-virtual {p1, v1, v2}, Ljava/lang/String;->substring(II)Ljava/lang/String;

    move-result-object v1

    const-string v2, "&"

    invoke-virtual {v1, v2}, Ljava/lang/String;->split(Ljava/lang/String;)[Ljava/lang/String;

    move-result-object v1

    array-length v2, v1

    const/4 v3, 0x0

    :goto_1c
    if-ge v3, v2, :cond_3c

    aget-object v4, v1, v3

    const-string v5, "="

    const/4 v6, 0x2

    invoke-virtual {v4, v5, v6}, Ljava/lang/String;->split(Ljava/lang/String;I)[Ljava/lang/String;

    move-result-object v4

    aget-object v5, v4, v3

    array-length v6, v4

    const/4 v7, 0x1

    if-le v6, v7, :cond_30

    aget-object v4, v4, v7

    goto :goto_32

    :cond_30
    const-string v4, ""

    :goto_32
    invoke-virtual {p0, v5, v4}, Lcom/example/apigateway/sdk/utils/Request;->addQueryStringParam(Ljava/lang/String;Ljava/lang/String;)V

    add-int/lit8 v3, v3, 0x1

    goto :goto_1c

    :cond_3c
    invoke-virtual {p1, v3, v0}, Ljava/lang/String;->substring(II)Ljava/lang/String;

    move-result-object p1

    iput-object p1, p0, Lcom/example/apigateway/sdk/utils/Request;->url:Ljava/lang/String;

    return-void
.end method

.method private addQueryStringParam(Ljava/lang/String;Ljava/lang/String;)V
    .registers 5

    iget-object v0, p0, Lcom/example/apigateway/sdk/utils/Request;->queryString:Ljava/util/Map;

    invoke-interface {v0, p1}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Ljava/util/List;

    if-nez v0, :cond_14

    new-instance v0, Ljava/util/ArrayList;

    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    iget-object v1, p0, Lcom/example/apigateway/sdk/utils/Request;->queryString:Ljava/util/Map;

    invoke-interface {v1, p1, v0}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    :cond_14
    invoke-interface {v0, p2}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    return-void
.end method
