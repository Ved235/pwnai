import os
import json
import argparse
from pathlib import Path

import faiss
import numpy as np
from openai import OpenAI
from dotenv import load_dotenv

INDEX_FILE = "index.faiss"
META_FILE = "metadata.json"

MODEL = "text-embedding-3-small"


load_dotenv()

client = OpenAI(api_key=os.environ["OPENAI_KEY"])


def read_documents(folder):
    docs = []

    for file in sorted(Path(folder).rglob("*.txt")):
        text = file.read_text(encoding="utf-8", errors="replace").strip()

        docs.append({
            "text": text,
            "path": str(file),
            "filename": file.name
        })

    return docs


def embed_texts(texts, batch_size=32):

    vectors = []

    for i in range(0, len(texts), batch_size):

        batch = texts[i:i+batch_size]

        response = client.embeddings.create(
            model=MODEL,
            input=batch
        )

        batch_vectors = [x.embedding for x in response.data]

        vectors.extend(batch_vectors)

    vectors = np.array(vectors).astype("float32")

    faiss.normalize_L2(vectors)

    return vectors


def build_index(vectors):
    dim = vectors.shape[1]

    index = faiss.IndexFlatIP(dim)

    index.add(vectors)

    return index


def build_db(args):

    docs = read_documents(args.docs)

    texts = [d["text"] for d in docs]

    vectors = embed_texts(texts)

    index = build_index(vectors)

    os.makedirs(args.db, exist_ok=True)

    faiss.write_index(index, f"{args.db}/{INDEX_FILE}")

    with open(f"{args.db}/{META_FILE}", "w") as f:
        json.dump(docs, f)

    print("Database built.")
    print("Documents:", len(docs))
    print("Embedding model:", MODEL)


def load_db(db):

    index = faiss.read_index(f"{db}/{INDEX_FILE}")

    with open(f"{db}/{META_FILE}") as f:
        metadata = json.load(f)

    return index, metadata


def query_db(args):

    index, metadata = load_db(args.db)

    query_vec = embed_texts([args.q])

    scores, ids = index.search(query_vec, args.top_k)

    print("\nQuery:", args.q)

    for rank, (score, idx) in enumerate(zip(scores[0], ids[0]), 1):

        doc = metadata[idx]

        print("\n==============================")
        print("Rank:", rank)
        print("Score:", score)
        print("File:", doc["filename"])
        print("Path:", doc["path"])
        print("------------------------------")
        print(doc["text"][:1500])


def main():

    parser = argparse.ArgumentParser()

    sub = parser.add_subparsers(dest="cmd")

    build = sub.add_parser("build")
    build.add_argument("--docs", required=True)
    build.add_argument("--db", required=True)
    build.set_defaults(func=build_db)

    query = sub.add_parser("query")
    query.add_argument("--db", required=True)
    query.add_argument("--q", required=True)
    query.add_argument("--top-k", type=int, default=5)
    query.set_defaults(func=query_db)

    args = parser.parse_args()

    args.func(args)


if __name__ == "__main__":
    main()