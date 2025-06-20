import time
import pandas as pd
import io
import sqlite3
import tempfile
import os
import google.generativeai as genai
from telegram import Update
from telegram.ext import ApplicationBuilder, CommandHandler, MessageHandler, ContextTypes, filters

# Configuración
TELEGRAM_TOKEN = "7267525734:AAEmakMjWGzblF0fAynA7S47Ru9G0a4g3bc"
GEMINI_API_KEY = "AIzaSyCl3wfjB3pLD3D_aON-kw_9zPKBVoHZR8s"
MAX_FILE_SIZE = 100 * 1024 * 1024  # 100MB

# Configurar Gemini
genai.configure(api_key=GEMINI_API_KEY)
model = genai.GenerativeModel(model_name="gemini-1.5-flash")

# Almacenamiento de datos por usuario
user_data = {}

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(
        "👋 ¡Hola! Envíame un archivo para analizar:\n\n"
        "📊 CSV - Para datos tabulares\n"
        "🗃️ SQL/DB - Bases de datos SQLite\n"
        "📝 SQL - Archivos de consultas SQL\n\n"
        "Límite de tamaño: 100MB"
    )

async def handle_file(update: Update, context: ContextTypes.DEFAULT_TYPE):
    start_time = time.time()
    file = await update.message.document.get_file()
    file_extension = update.message.document.file_name.split('.')[-1].lower()
    
    # Verificar tamaño del archivo
    if file.file_size > MAX_FILE_SIZE:
        await update.message.reply_text(f"⚠️ Archivo demasiado grande ({(file.file_size/1024/1024):.1f}MB). Límite: {MAX_FILE_SIZE/1024/1024}MB")
        return
    
    msg = await update.message.reply_text("📥 Descargando archivo...")
    
    try:
        content = await file.download_as_bytearray()
        
        # Procesamiento según tipo de archivo
        if file_extension in ['csv']:
            await process_csv(update, msg, content)
        elif file_extension in ['db', 'sqlite', 'sqlite3']:
            await process_sqlite_db(update, msg, content)
        elif file_extension == 'sql':
            await process_sql_file(update, msg, content)
        else:
            await msg.edit_text("⚠️ Formato no soportado. Envíe CSV, DB o SQL.")
            
    except Exception as e:
        await msg.edit_text(f"❌ Error: {str(e)}")

async def process_csv(update: Update, msg, content):
    await msg.edit_text("🔍 Analizando estructura del CSV...")
    
    # Leer solo las primeras líneas para detectar estructura
    with io.BytesIO(content) as file_stream:
        # Primera pasada: detectar columnas y tipos
        df_sample = pd.read_csv(file_stream, nrows=100)
        file_stream.seek(0)
        
        # Segunda pasada: conteo aproximado de filas (más rápido que leer todo)
        row_count = sum(1 for _ in file_stream) - 1  # Restamos el header
        
    await msg.edit_text(f"⚙️ Procesando {row_count:,} filas...")
    
    # Muestreo inteligente para archivos grandes
    if row_count <= 10000:
        # Archivo pequeño: cargar completo
        df = pd.read_csv(io.BytesIO(content))
        sample_method = "Completo"
    else:
        # Archivo grande: muestreo estratificado
        await msg.edit_text("📊 Muestreo representativo de datos grandes...")
        
        # Calcular tamaño de muestra (máx 10,000 filas)
        sample_size = min(10000, max(1000, int(row_count * 0.01)))
        chunks = pd.read_csv(io.BytesIO(content), chunksize=10000)
        
        samples = []
        for i, chunk in enumerate(chunks):
            # Muestreo proporcional del chunk
            chunk_sample = chunk.sample(int(sample_size * len(chunk)/row_count))
            samples.append(chunk_sample)
            if i % 10 == 0:
                await msg.edit_text(f"📊 Procesando chunk {i}...")
        
        df = pd.concat(samples)
        sample_method = f"Muestra estratificada de {len(df):,} filas"
    
    # Almacenar metadatos
    user_data[update.message.chat_id] = {
        'type': 'csv',
        'full_size': row_count,
        'sample_size': len(df),
        'sample_method': sample_method,
        'columns': df_sample.columns.tolist(),
        'dtypes': str(df_sample.dtypes.to_dict()),
        'df': df,
        'tables': None,
        'db_schema': None
    }
    
    await send_file_analysis_response(update, msg, row_count, sample_method, df_sample.columns)

async def process_sqlite_db(update: Update, msg, content):
    await msg.edit_text("🔍 Analizando base de datos SQLite...")
    
    # Guardar temporalmente el archivo para poder conectarse
    with tempfile.NamedTemporaryFile(delete=False) as tmp_file:
        tmp_file.write(content)
        tmp_file_path = tmp_file.name
    
    try:
        conn = sqlite3.connect(tmp_file_path)
        cursor = conn.cursor()
        
        # Obtener lista de tablas
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
        tables = cursor.fetchall()
        table_names = [table[0] for table in tables]
        
        # Obtener esquema de cada tabla
        db_schema = {}
        sample_data = {}
        
        for table in table_names:
            # Obtener estructura de la tabla
            cursor.execute(f"PRAGMA table_info({table});")
            columns = cursor.fetchall()
            column_names = [col[1] for col in columns]
            
            # Obtener conteo de filas
            cursor.execute(f"SELECT COUNT(*) FROM {table};")
            row_count = cursor.fetchone()[0]
            
            # Obtener muestra de datos
            cursor.execute(f"SELECT * FROM {table} LIMIT 100;")
            sample_rows = cursor.fetchall()
            
            db_schema[table] = {
                'columns': column_names,
                'row_count': row_count,
                'sample': sample_rows
            }
            
            # Crear DataFrame con la muestra para análisis
            df_sample = pd.DataFrame(sample_rows, columns=column_names)
            sample_data[table] = df_sample
        
        conn.close()
        
        # Almacenar metadatos
        user_data[update.message.chat_id] = {
            'type': 'sqlite',
            'tables': table_names,
            'db_schema': db_schema,
            'sample_data': sample_data,
            'db_path': tmp_file_path,  # Guardamos la ruta para consultas posteriores
            'current_table': table_names[0] if table_names else None
        }
        
        # Construir respuesta
        response = "✅ Base de datos SQLite analizada\n\n"
        response += f"📊 Tablas encontradas ({len(table_names)}):\n"
        response += "\n".join([f"- {table} ({db_schema[table]['row_count']:,} filas)" for table in table_names[:5]])
        
        if len(table_names) > 5:
            response += f"\n... y {len(table_names)-5} más"
            
        response += "\n\n💡 Puedes preguntar por:\n"
        response += "- Datos de una tabla específica (/usar <tabla>)\n"
        response += "- Estructura de una tabla (/schema <tabla>)\n"
        response += "- Consultas SQL específicas"
        
        await msg.edit_text(response)
        
    except Exception as e:
        await msg.edit_text(f"❌ Error al analizar la base de datos: {str(e)}")
    finally:
        # No eliminamos el archivo temporal porque lo necesitaremos para consultas
        pass

async def process_sql_file(update: Update, msg, content):
    await msg.edit_text("🔍 Analizando archivo SQL...")
    
    sql_content = content.decode('utf-8')
    
    # Almacenar el contenido SQL
    user_data[update.message.chat_id] = {
        'type': 'sql',
        'sql_content': sql_content,
        'tables': extract_tables_from_sql(sql_content)
    }
    
    response = "✅ Archivo SQL analizado\n\n"
    response += f"📝 Longitud: {len(sql_content.splitlines())} líneas\n"
    
    tables = user_data[update.message.chat_id]['tables']
    if tables:
        response += f"📊 Tablas mencionadas: {', '.join(tables)}\n"
    
    response += "\n💡 Puedes preguntar por:\n"
    response += "- Consultas específicas en el archivo\n"
    response += "- Explicación del esquema\n"
    response += "- Modificaciones sugeridas"
    
    await msg.edit_text(response)

def extract_tables_from_sql(sql_content):
    # Simple extracción de nombres de tablas (mejorable)
    tables = set()
    keywords = ['FROM', 'JOIN', 'INTO', 'UPDATE', 'TABLE']
    
    for line in sql_content.split('\n'):
        line_upper = line.upper()
        for kw in keywords:
            if kw in line_upper:
                parts = line_upper.split(kw)
                if len(parts) > 1:
                    table_part = parts[1].split()[0].strip('`\'"')
                    if table_part:
                        tables.add(table_part)
    return list(tables)

async def send_file_analysis_response(update, msg, row_count, sample_method, columns):
    processing_time = time.time() - msg.date.timestamp()
    response = (
        f"✅ CSV analizado ({row_count:,} filas)\n\n"
        f"📊 Método: {sample_method}\n"
        f"⏱ Tiempo: {processing_time:.1f}s\n\n"
        f"🔡 Columnas ({len(columns)}):\n{', '.join(columns[:5])}"
    )
    
    if len(columns) > 5:
        response += f" + {len(columns)-5} más...\n\n"
    
    response += (
        f"\n💡 Puedes preguntar por:\n"
        f"- Nombres de columnas específicas\n"
        f"- Análisis de datos\n"
        f"- Patrones o tendencias"
    )
    
    await msg.edit_text(response)

async def handle_question(update: Update, context: ContextTypes.DEFAULT_TYPE):
    chat_id = update.message.chat_id
    if chat_id not in user_data:
        await update.message.reply_text("⚠️ Primero envía un archivo para analizar.")
        return

    data_info = user_data[chat_id]
    question = update.message.text

    # Comandos especiales para todos los tipos
    if question.lower() == '/metadata':
        await handle_metadata(update, data_info)
        return
    
    # Manejo específico por tipo de archivo
    if data_info['type'] == 'csv':
        await handle_csv_question(update, data_info, question)
    elif data_info['type'] == 'sqlite':
        await handle_sqlite_question(update, data_info, question)
    elif data_info['type'] == 'sql':
        await handle_sql_question(update, data_info, question)

async def handle_metadata(update: Update, data_info):
    if data_info['type'] == 'csv':
        response = (
            f"📊 Metadatos del CSV:\n"
            f"- Filas totales: {data_info['full_size']:,}\n"
            f"- Filas analizadas: {data_info['sample_size']:,}\n"
            f"- Método: {data_info['sample_method']}\n"
            f"- Columnas: {len(data_info['columns'])}\n"
            f"- Tipos de datos:\n{data_info['dtypes']}"
        )
    elif data_info['type'] == 'sqlite':
        response = "📊 Metadatos de la base de datos SQLite:\n"
        response += f"- Tablas: {len(data_info['tables'])}\n"
        for table in data_info['tables']:
            schema = data_info['db_schema'][table]
            response += (
                f"\n📌 Tabla: {table}\n"
                f"- Filas: {schema['row_count']:,}\n"
                f"- Columnas: {len(schema['columns'])}\n"
                f"- Muestra: {len(schema['sample'])} filas"
            )
    elif data_info['type'] == 'sql':
        response = (
            f"📝 Metadatos del archivo SQL:\n"
            f"- Longitud: {len(data_info['sql_content'].splitlines())} líneas\n"
            f"- Tablas mencionadas: {', '.join(data_info['tables']) if data_info['tables'] else 'Ninguna'}"
        )
    
    await update.message.reply_text(response)

async def handle_csv_question(update: Update, data_info, question):
    df = data_info['df']
    
    # Pregunta por nombre de columna
    if question.lower() in map(str.lower, data_info['columns']):
        col = [c for c in data_info['columns'] if c.lower() == question.lower()][0]
        sample = df[col].dropna().sample(min(5, len(df))).tolist()
        response = (
            f"📊 Columna: {col}\n"
            f"- Tipo: {df[col].dtype}\n"
            f"- Valores únicos: {df[col].nunique():,}\n"
            f"- Nulos: {df[col].isna().sum():,} ({df[col].isna().mean()*100:.1f}%)\n"
            f"- Ejemplos:\n"
        ) + "\n".join(map(str, sample))
        await update.message.reply_text(response)
        return
    
    # Consulta general
    await handle_general_question(update, data_info, question, df)

async def handle_sqlite_question(update: Update, data_info, question):
    # Comandos específicos para SQLite
    if question.lower().startswith('/usar '):
        table_name = question[6:].strip()
        if table_name in data_info['tables']:
            data_info['current_table'] = table_name
            schema = data_info['db_schema'][table_name]
            await update.message.reply_text(
                f"✅ Tabla {table_name} seleccionada\n\n"
                f"📊 Columnas: {', '.join(schema['columns'])}\n"
                f"📈 Filas totales: {schema['row_count']:,}"
            )
        else:
            await update.message.reply_text(f"⚠️ Tabla no encontrada. Tablas disponibles: {', '.join(data_info['tables'])}")
        return
    
    if question.lower().startswith('/schema '):
        table_name = question[8:].strip()
        if table_name in data_info['tables']:
            schema = data_info['db_schema'][table_name]
            response = f"📐 Esquema de la tabla {table_name}:\n\n"
            response += "\n".join([f"- {col}: {type}" for col in schema['columns']])
            await update.message.reply_text(response)
        else:
            await update.message.reply_text(f"⚠️ Tabla no encontrada. Tablas disponibles: {', '.join(data_info['tables'])}")
        return
    
    # Si no hay tabla seleccionada
    if not data_info['current_table']:
        await update.message.reply_text(
            "⚠️ Primero selecciona una tabla con /usar <tabla>\n\n"
            f"Tablas disponibles: {', '.join(data_info['tables'])}"
        )
        return
    
    # Consulta sobre la tabla actual
    table_name = data_info['current_table']
    schema = data_info['db_schema'][table_name]
    df = data_info['sample_data'][table_name]
    
    # Pregunta por nombre de columna
    if question.lower() in map(str.lower, schema['columns']):
        col = [c for c in schema['columns'] if c.lower() == question.lower()][0]
        sample = df[col].dropna().sample(min(5, len(df))).tolist()
        response = (
            f"📊 Columna: {col}\n"
            f"- Tipo: {df[col].dtype}\n"
            f"- Valores únicos: {df[col].nunique():,}\n"
            f"- Nulos: {df[col].isna().sum():,}\n"
            f"- Ejemplos:\n"
        ) + "\n".join(map(str, sample))
        await update.message.reply_text(response)
        return
    
    # Consulta general
    await handle_general_question(update, data_info, question, df)

async def handle_sql_question(update: Update, data_info, question):
    # Consulta sobre el contenido SQL
    msg = await update.message.reply_text("🔍 Analizando consulta SQL...")
    
    try:
        prompt = (
            f"Tengo un archivo SQL con el siguiente contenido:\n\n"
            f"{data_info['sql_content']}\n\n"
            f"Pregunta: {question}\n\n"
            f"Instrucciones:\n"
            f"- Responde en español\n"
            f"- Si la pregunta es sobre el esquema, menciona las tablas relevantes\n"
            f"- Si es sobre consultas específicas, explícalas claramente\n"
            f"- Proporciona ejemplos cuando sea posible"
        )
        
        response = model.generate_content(prompt)
        await msg.edit_text(response.text)
    except Exception as e:
        await msg.edit_text(f"🚨 Error: {str(e)}")

async def handle_general_question(update: Update, data_info, question, df):
    msg = await update.message.reply_text("🔍 Consultando Gemini...")

    try:
        # Preparar datos para Gemini según el tipo
        if data_info['type'] == 'csv':
            if data_info['full_size'] <= 10000:
                data_str = df.to_csv(index=False)
                data_note = f"Datos completos ({len(df):,} filas)"
            else:
                data_str = (
                    f"Muestra representativa de {len(df):,} filas (de {data_info['full_size']:,} totales)\n"
                    f"{df.sample(min(1000, len(df))).to_csv(index=False)}\n\n"
                    f"Estadísticas resumidas:\n{df.describe().to_csv()}"
                )
                data_note = f"Muestra de {len(df):,} filas"
                
            prompt = (
                f"Analiza estos datos CSV:\n\n"
                f"METADATOS:\n"
                f"- Filas totales: {data_info['full_size']:,}\n"
                f"- Filas proporcionadas: {len(df):,}\n"
                f"- Método de muestreo: {data_info['sample_method']}\n"
                f"- Columnas: {', '.join(data_info['columns'])}\n\n"
                f"DATOS:\n{data_str}\n\n"
                f"PREGUNTA: {question}\n\n"
                f"Instrucciones:\n"
                f"- Responde en español\n"
                f"- Si la pregunta requiere todos los datos pero solo tienes una muestra, acláralo\n"
                f"- Proporciona análisis cuantitativo cuando sea posible\n"
                f"- Sé conciso pero informativo"
            )
            
        elif data_info['type'] == 'sqlite':
            table_name = data_info['current_table']
            schema = data_info['db_schema'][table_name]
            
            data_str = (
                f"Tabla: {table_name}\n"
                f"Filas totales: {schema['row_count']:,}\n"
                f"Columnas: {', '.join(schema['columns'])}\n\n"
                f"Muestra de datos (100 filas):\n"
                f"{df.to_csv(index=False)}\n\n"
                f"Estadísticas resumidas:\n{df.describe().to_csv()}"
            )
            data_note = f"Tabla {table_name} ({schema['row_count']:,} filas)"
            
            prompt = (
                f"Analiza estos datos de SQLite:\n\n"
                f"METADATOS:\n"
                f"- Base de datos con {len(data_info['tables'])} tablas\n"
                f"- Tabla actual: {table_name}\n"
                f"- Columnas: {', '.join(schema['columns'])}\n\n"
                f"DATOS:\n{data_str}\n\n"
                f"PREGUNTA: {question}\n\n"
                f"Instrucciones:\n"
                f"- Responde en español\n"
                f"- Si la pregunta requiere consultas SQL adicionales, sugiérelas\n"
                f"- Proporciona análisis cuantitativo cuando sea posible\n"
                f"- Considera que solo tienes una muestra de los datos"
            )
        
        response = model.generate_content(prompt)
        
        # Formatear respuesta
        full_response = f"{response.text}\n\n"
        
        # Dividir respuestas largas
        if len(full_response) > 4000:
            parts = [full_response[i:i+4000] for i in range(0, len(full_response), 4000)]
            for part in parts:
                await update.message.reply_text(part)
                time.sleep(1)
        else:
            await msg.edit_text(full_response)

    except Exception as e:
        await msg.edit_text(f"🚨 Error: {str(e)}")

if __name__ == "__main__":
    app = ApplicationBuilder().token(TELEGRAM_TOKEN).build()
    app.add_handler(CommandHandler("start", start))
    app.add_handler(MessageHandler(
        filters.Document.FileExtension("csv") | 
        filters.Document.FileExtension("db") |
        filters.Document.FileExtension("sqlite") |
        filters.Document.FileExtension("sqlite3") |
        filters.Document.FileExtension("sql"), 
        handle_file))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_question))
    print("🤖 Bot avanzado para análisis de datos funcionando...")
    app.run_polling()
