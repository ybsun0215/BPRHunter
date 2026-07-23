.class public final enum Lcom/example/sdk/http/HttpMethodName;
.super Ljava/lang/Enum;
.source "HttpMethodName.java"


# annotations
.annotation system Ldalvik/annotation/Signature;
    value = {
        "Ljava/lang/Enum<",
        "Lcom/example/sdk/http/HttpMethodName;",
        ">;"
    }
.end annotation


# static fields
.field public static final enum DELETE:Lcom/example/sdk/http/HttpMethodName;

.field public static final enum GET:Lcom/example/sdk/http/HttpMethodName;

.field public static final enum HEAD:Lcom/example/sdk/http/HttpMethodName;

.field public static final enum OPTIONS:Lcom/example/sdk/http/HttpMethodName;

.field public static final enum PATCH:Lcom/example/sdk/http/HttpMethodName;

.field public static final enum POST:Lcom/example/sdk/http/HttpMethodName;

.field public static final enum PUT:Lcom/example/sdk/http/HttpMethodName;


# direct methods
.method static constructor <clinit>()V
    .registers 3

    new-instance v0, Lcom/example/sdk/http/HttpMethodName;

    const-string v1, "GET"

    const/4 v2, 0x0

    invoke-direct {v0, v1, v2}, Lcom/example/sdk/http/HttpMethodName;-><init>(Ljava/lang/String;I)V

    sput-object v0, Lcom/example/sdk/http/HttpMethodName;->GET:Lcom/example/sdk/http/HttpMethodName;

    new-instance v0, Lcom/example/sdk/http/HttpMethodName;

    const-string v1, "POST"

    const/4 v2, 0x1

    invoke-direct {v0, v1, v2}, Lcom/example/sdk/http/HttpMethodName;-><init>(Ljava/lang/String;I)V

    sput-object v0, Lcom/example/sdk/http/HttpMethodName;->POST:Lcom/example/sdk/http/HttpMethodName;

    new-instance v0, Lcom/example/sdk/http/HttpMethodName;

    const-string v1, "PUT"

    const/4 v2, 0x2

    invoke-direct {v0, v1, v2}, Lcom/example/sdk/http/HttpMethodName;-><init>(Ljava/lang/String;I)V

    sput-object v0, Lcom/example/sdk/http/HttpMethodName;->PUT:Lcom/example/sdk/http/HttpMethodName;

    new-instance v0, Lcom/example/sdk/http/HttpMethodName;

    const-string v1, "PATCH"

    const/4 v2, 0x3

    invoke-direct {v0, v1, v2}, Lcom/example/sdk/http/HttpMethodName;-><init>(Ljava/lang/String;I)V

    sput-object v0, Lcom/example/sdk/http/HttpMethodName;->PATCH:Lcom/example/sdk/http/HttpMethodName;

    new-instance v0, Lcom/example/sdk/http/HttpMethodName;

    const-string v1, "DELETE"

    const/4 v2, 0x4

    invoke-direct {v0, v1, v2}, Lcom/example/sdk/http/HttpMethodName;-><init>(Ljava/lang/String;I)V

    sput-object v0, Lcom/example/sdk/http/HttpMethodName;->DELETE:Lcom/example/sdk/http/HttpMethodName;

    new-instance v0, Lcom/example/sdk/http/HttpMethodName;

    const-string v1, "HEAD"

    const/4 v2, 0x5

    invoke-direct {v0, v1, v2}, Lcom/example/sdk/http/HttpMethodName;-><init>(Ljava/lang/String;I)V

    sput-object v0, Lcom/example/sdk/http/HttpMethodName;->HEAD:Lcom/example/sdk/http/HttpMethodName;

    new-instance v0, Lcom/example/sdk/http/HttpMethodName;

    const-string v1, "OPTIONS"

    const/4 v2, 0x6

    invoke-direct {v0, v1, v2}, Lcom/example/sdk/http/HttpMethodName;-><init>(Ljava/lang/String;I)V

    sput-object v0, Lcom/example/sdk/http/HttpMethodName;->OPTIONS:Lcom/example/sdk/http/HttpMethodName;

    return-void
.end method

.method private constructor <init>(Ljava/lang/String;I)V
    .registers 3
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()V"
        }
    .end annotation

    invoke-direct {p0, p1, p2}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    return-void
.end method
