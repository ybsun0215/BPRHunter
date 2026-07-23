.class public Lcom/example/apigateway/sdk/utils/AccessService;
.super Ljava/lang/Object;
.source "AccessService.smali"


.field private static final VF_SIGN_HEADER:Ljava/lang/String; = "v587sign"

.field private static final DATE_HEADER:Ljava/lang/String; = "x-sdk-date"

.field private static final TIMESTAMP_HEADER:Ljava/lang/String; = "x-ca-timestamp"


.method public static signRequest(Lokhttp3/Request$Builder;)Lokhttp3/Request$Builder;
    .locals 4

    const-string v0, "x-sdk-date"

    invoke-static {}, Ljava/util/TimeZone;->getTimeZone(Ljava/lang/String;)Ljava/util/TimeZone;

    new-instance v1, Ljava/text/SimpleDateFormat;

    const-string v2, "yyyyMMdd'T'HHmmss'Z'"

    invoke-direct {v1, v2}, Ljava/text/SimpleDateFormat;-><init>(Ljava/lang/String;)V

    const-string v2, "UTC"

    invoke-static {v2}, Ljava/util/TimeZone;->getTimeZone(Ljava/lang/String;)Ljava/util/TimeZone;

    move-result-object v2

    invoke-virtual {v1, v2}, Ljava/text/SimpleDateFormat;->setTimeZone(Ljava/util/TimeZone;)V

    new-instance v2, Ljava/util/Date;

    invoke-direct {v2}, Ljava/util/Date;-><init>()V

    invoke-virtual {v1, v2}, Ljava/text/SimpleDateFormat;->format(Ljava/util/Date;)Ljava/lang/String;

    move-result-object v1

    invoke-virtual {p0, v0, v1}, Lokhttp3/Request$Builder;->addHeader(Ljava/lang/String;Ljava/lang/String;)Lokhttp3/Request$Builder;

    const-string v0, "x-ca-timestamp"

    invoke-static {}, Ljava/lang/System;->currentTimeMillis()J

    move-result-wide v1

    invoke-static {v1, v2}, Ljava/lang/String;->valueOf(J)Ljava/lang/String;

    move-result-object v1

    invoke-virtual {p0, v0, v1}, Lokhttp3/Request$Builder;->addHeader(Ljava/lang/String;Ljava/lang/String;)Lokhttp3/Request$Builder;

    const-string v0, "v587sign"

    invoke-static {p0}, Lcom/example/sdk/util/SignUtils;->computeV587sign(Ljava/util/Map;)Ljava/lang/String;

    move-result-object v1

    invoke-virtual {p0, v0, v1}, Lokhttp3/Request$Builder;->addHeader(Ljava/lang/String;Ljava/lang/String;)Lokhttp3/Request$Builder;

    return-object p0
.end method
