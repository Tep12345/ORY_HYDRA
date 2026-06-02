# ORY Hydra Authentication and Authorization Service

Hydra を OAuth2/OIDC 認可サーバとして使う最小構成です。Hydra はログイン画面やユーザー管理を持たないため、このリポジトリでは Express でログイン UI、同意 UI、サンプル OAuth クライアントを実装しています。

## 構成

- `hydra`: OAuth2/OIDC public/admin API
- `postgres`: Hydra の永続化 DB
- `app`: ログイン UI、同意 UI、サンプルクライアント

`app` は起動時に Hydra Admin API を使い、デモ OAuth クライアントが存在しなければ登録します。

## 起動

```powershell
docker compose up --build
```

起動後、ブラウザで次を開きます。

```text
http://localhost:3001
```

デモログイン情報:

```text
alice@example.com
password
```

## 主要 URL

- `http://localhost:3001`: サンプル OAuth クライアント
- `http://localhost:3000/login`: Hydra から呼ばれるログイン UI
- `http://localhost:3000/consent`: Hydra から呼ばれる同意 UI
- `http://localhost:4444`: Hydra public endpoint
- `http://localhost:4445`: Hydra admin endpoint

## 本番化で必ず変更すること

- `SECRETS_SYSTEM` と `SESSION_SECRET` を強いランダム値に変更する
- `--dev` を外し、issuer と redirect URI を HTTPS の正式 URL にする
- Hydra admin endpoint を外部公開しない
- Express のデモユーザーを実ユーザー DB、パスワードハッシュ、MFA などに置き換える
- Cookie に `secure: true` を設定する
- OAuth クライアント登録を IaC または管理 API 経由の正式な運用にする
