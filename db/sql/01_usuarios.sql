-- Executado automaticamente pelo container MySQL na primeira subida
-- (montar ./db/sql em /docker-entrypoint-initdb.d). Mesmo schema de db/mysql_repo.py.
-- Baseado na tabela usuarios da Aula 1.2 da apostila, com as restricoes da GS.
CREATE TABLE IF NOT EXISTS usuarios (
    id           INT AUTO_INCREMENT PRIMARY KEY,
    nome         VARCHAR(100) NOT NULL,
    email        VARCHAR(150) NOT NULL UNIQUE,
    senha_hash   VARCHAR(255) NOT NULL,
    nivel_acesso INT NOT NULL DEFAULT 1,
    ativo        BOOLEAN NOT NULL DEFAULT TRUE,
    criado_em    TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    CHECK (nivel_acesso BETWEEN 1 AND 5)
);
