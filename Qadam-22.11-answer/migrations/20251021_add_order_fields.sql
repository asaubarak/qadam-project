-- Добавляем поле order для упорядочивания элементов
-- Блоки
ALTER TABLE blocks ADD COLUMN IF NOT EXISTS "order" INTEGER DEFAULT 0;

-- Варианты
ALTER TABLE variants ADD COLUMN IF NOT EXISTS "order" INTEGER DEFAULT 0;

-- Предметы
ALTER TABLE subjects ADD COLUMN IF NOT EXISTS "order" INTEGER DEFAULT 0;

-- Вопросы
ALTER TABLE questions ADD COLUMN IF NOT EXISTS "order" INTEGER DEFAULT 0;

-- Ответы
ALTER TABLE answers ADD COLUMN IF NOT EXISTS "order" INTEGER DEFAULT 0;

-- Устанавливаем начальный порядок на основе существующих данных
UPDATE blocks SET "order" = sub.row_num - 1
FROM (
  SELECT id, ROW_NUMBER() OVER (ORDER BY id) as row_num 
  FROM blocks
) sub
WHERE blocks.id = sub.id;

UPDATE variants SET "order" = sub.row_num - 1
FROM (
  SELECT id, ROW_NUMBER() OVER (PARTITION BY block_id ORDER BY id) as row_num 
  FROM variants
) sub
WHERE variants.id = sub.id;

UPDATE subjects SET "order" = sub.row_num - 1
FROM (
  SELECT id, ROW_NUMBER() OVER (PARTITION BY variant_id ORDER BY id) as row_num 
  FROM subjects
) sub
WHERE subjects.id = sub.id;

UPDATE questions SET "order" = sub.row_num - 1
FROM (
  SELECT id, ROW_NUMBER() OVER (PARTITION BY subject_id ORDER BY id) as row_num 
  FROM questions
) sub
WHERE questions.id = sub.id;

UPDATE answers SET "order" = sub.row_num - 1
FROM (
  SELECT id, ROW_NUMBER() OVER (PARTITION BY question_id ORDER BY id) as row_num 
  FROM answers
) sub
WHERE answers.id = sub.id;
