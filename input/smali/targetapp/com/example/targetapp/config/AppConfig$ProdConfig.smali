.class public final Lcom/example/targetapp/config/AppConfig$ProdConfig;
.super Lcom/example/targetapp/config/AppConfig;
.source "AppConfig.smali"


# static fields
.field public static final ACCESS_KEY:Ljava/lang/String; = "PLACEHOLDER_ACCESS"

.field public static final SECRET_KEY:Ljava/lang/String; = "PLACEHOLDER_SECRET"

.field public static final VF_HEADER:Ljava/lang/String; = "sign"

.field public static final DATE_HEADER:Ljava/lang/String; = "x-demo-date"

.field public static final TIMESTAMP_HEADER:Ljava/lang/String; = "x-demo-timestamp"


# direct methods
.method public constructor <init>()V
    .registers 1

    invoke-direct {p0}, Lcom/example/targetapp/config/AppConfig;-><init>()V

    return-void
.end method
