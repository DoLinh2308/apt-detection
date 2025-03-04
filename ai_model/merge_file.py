import pandas as pd
import os

directory = "dataset/DAPT-2020/csv"

csv_files = [f for f in os.listdir(directory) if f.endswith(".csv")]
df_list = [pd.read_csv(os.path.join(directory, file), low_memory=False) for file in csv_files]
output_file = "data/DAPT-2020/merged_cleaned.csv"
df = pd.concat(df_list, ignore_index=True)

df = df.dropna(subset=["Activity", "Stage"])

if "Activity" in df.columns and "Stage" in df.columns:
    unique_activity = df["Activity"].unique()
    unique_stage = df["Stage"].unique()

    print("🔹 Danh sách giá trị không trùng trong 'activity':")
    print(unique_activity)
    
    print("\n🔹 Danh sách giá trị không trùng trong 'stage':")
    print(unique_stage)
else:
    print("⚠️ Dataset không có cột 'activity' hoặc 'stage', cần kiểm tra lại dữ liệu!")
# df.to_csv(output_file, index=False)