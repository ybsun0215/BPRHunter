.class public final enum Lcom/example/sdk/auth/signer/SigningAlgorithm;
.super Ljava/lang/Enum;
.source "SigningAlgorithm.java"


# annotations
.annotation system Ldalvik/annotation/Signature;
    value = {
        "Ljava/lang/Enum<",
        "Lcom/example/sdk/auth/signer/SigningAlgorithm;",
        ">;"
    }
.end annotation


# static fields
.field public static final enum HmacSHA256:Lcom/example/sdk/auth/signer/SigningAlgorithm;


# direct methods
.method static constructor <clinit>()V
    .registers 3

    new-instance v0, Lcom/example/sdk/auth/signer/SigningAlgorithm;

    const-string v1, "HmacSHA256"

    const/4 v2, 0x0

    invoke-direct {v0, v1, v2}, Lcom/example/sdk/auth/signer/SigningAlgorithm;-><init>(Ljava/lang/String;I)V

    sput-object v0, Lcom/example/sdk/auth/signer/SigningAlgorithm;->HmacSHA256:Lcom/example/sdk/auth/signer/SigningAlgorithm;

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
