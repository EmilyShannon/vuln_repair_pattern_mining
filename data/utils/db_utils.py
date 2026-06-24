import pandas as pd
import sqlite3
import os

def load_tables(db_path, chunksize=10000):
    # load each table from the DB in chunks
    conn = sqlite3.connect(db_path)
    # TODO change to a variable list of tables
    tables = pd.read_sql("SELECT name FROM sqlite_master WHERE type='table';", conn)
    # tables = pd.read_sql("SELECT name FROM sqlite_master WHERE type='table' AND name IN ('fixes', 'commits', 'file_change', 'cve', 'cwe', 'cwe_classification');", conn)
    
    dfs = {}
    for table_name in tables["name"]:
        print(f"\nStreaming {table_name} in chunks of {chunksize} rows...")
        chunk_iter = pd.read_sql(f"SELECT * FROM {table_name};", conn, chunksize=chunksize)
        total_rows = 0
        chunks = []

        # store each chunk 
        for chunk_num, chunk in enumerate(chunk_iter, start=1):
            rows = len(chunk)
            total_rows += rows
            print(f"Chunk {chunk_num}: {rows} rows")
            # chunk.to_csv(f"{table_name}_chunk{chunk_num}.csv", index=False)  # store each chunk to a CSV file
            chunks.append(chunk) # store chunk in list

            # break early if only testing w/ preview 
            # if chunk_num == 2:
            #     break

        print(f"Finished {table_name} ({total_rows} total rows)")
        dfs[table_name] = pd.concat(chunks, ignore_index=True)  
    conn.close()
    return dfs

def show_tables(tables):
    for table_name in tables.keys():
        print(tables[table_name].info())

def save_desired_columns(tables_columns, project_name, tables):
    # save specified columns from each table to 
    output_dir = "../Data/extracted_data"
    output_path = f"{output_dir}/{project_name}.csv"
    os.makedirs(output_dir, exist_ok=True)
    
    for table_name, columns in tables_columns.items():
        # concatenate the desired columns from each table into a single DataFrame
        compiled_df = pd.DataFrame()
        if table_name in tables:
            df = tables[table_name]
            if columns and columns != []:
                missing_cols = [col for col in columns if col not in df.columns]
                if missing_cols:
                    print(f"Warning: missing columns {missing_cols} in table {table_name}")
                df = df[[col for col in columns if col in df.columns]]
            compiled_df = pd.concat([compiled_df, df], ignore_index=True)
                # output_path = os.path.join(output_dir, f"{table_name}.csv")
            # df.to_csv(output_path, index=False)
            # print(f"Saved {table_name} to {output_path}")
        else:
            print(f"Warning: table {table_name} not found in database")
    compiled_df.to_csv(output_path, index=False)


def dump_sql(sql_path, db_path):
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    # Execute the .sql dump in chunks to avoid memory overload
    with open(sql_path, "r", encoding="utf-8", errors="ignore") as f:
        sql_script = ""
        for line in f:
            sql_script += line
            if line.strip().endswith(";"):
                try:
                    cursor.executescript(sql_script)
                    sql_script = ""
                except Exception as e:
                    print("Error:", e)
                    sql_script = ""
        conn.commit()

    conn.close()
    print("SQL file imported successfully!")