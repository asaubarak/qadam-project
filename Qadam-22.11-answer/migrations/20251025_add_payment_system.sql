-- Создание таблиц для системы платежей
CREATE TABLE IF NOT EXISTS "subscription_plans" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid(),
	"name" text NOT NULL,
	"description" text,
	"price" integer NOT NULL,
	"currency" text DEFAULT 'RUB' NOT NULL,
	"duration_days" integer NOT NULL,
	"features" jsonb DEFAULT '[]' NOT NULL,
	"is_active" boolean DEFAULT true,
	"sort_order" integer DEFAULT 0,
	"created_at" timestamp DEFAULT now(),
	"updated_at" timestamp DEFAULT now()
);

CREATE TABLE IF NOT EXISTS "user_subscriptions" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid(),
	"user_id" varchar NOT NULL,
	"plan_id" varchar NOT NULL,
	"status" text DEFAULT 'PENDING' NOT NULL,
	"start_date" timestamp,
	"end_date" timestamp,
	"auto_renew" boolean DEFAULT false,
	"created_at" timestamp DEFAULT now(),
	"updated_at" timestamp DEFAULT now()
);

CREATE TABLE IF NOT EXISTS "payments" (
	"id" varchar PRIMARY KEY DEFAULT gen_random_uuid(),
	"user_id" varchar NOT NULL,
	"subscription_id" varchar,
	"plan_id" varchar NOT NULL,
	"amount" integer NOT NULL,
	"currency" text DEFAULT 'RUB' NOT NULL,
	"status" text DEFAULT 'PENDING' NOT NULL,
	"payment_method" text,
	"external_payment_id" text,
	"payment_data" jsonb,
	"created_at" timestamp DEFAULT now(),
	"completed_at" timestamp
);

-- Добавляем внешние ключи
DO $$ BEGIN
 ALTER TABLE "user_subscriptions" ADD CONSTRAINT "user_subscriptions_user_id_users_id_fk" FOREIGN KEY ("user_id") REFERENCES "users"("id") ON DELETE cascade ON UPDATE no action;
EXCEPTION
 WHEN duplicate_object THEN null;
END $$;

DO $$ BEGIN
 ALTER TABLE "user_subscriptions" ADD CONSTRAINT "user_subscriptions_plan_id_subscription_plans_id_fk" FOREIGN KEY ("plan_id") REFERENCES "subscription_plans"("id") ON DELETE no action ON UPDATE no action;
EXCEPTION
 WHEN duplicate_object THEN null;
END $$;

DO $$ BEGIN
 ALTER TABLE "payments" ADD CONSTRAINT "payments_user_id_users_id_fk" FOREIGN KEY ("user_id") REFERENCES "users"("id") ON DELETE cascade ON UPDATE no action;
EXCEPTION
 WHEN duplicate_object THEN null;
END $$;

DO $$ BEGIN
 ALTER TABLE "payments" ADD CONSTRAINT "payments_subscription_id_user_subscriptions_id_fk" FOREIGN KEY ("subscription_id") REFERENCES "user_subscriptions"("id") ON DELETE no action ON UPDATE no action;
EXCEPTION
 WHEN duplicate_object THEN null;
END $$;

DO $$ BEGIN
 ALTER TABLE "payments" ADD CONSTRAINT "payments_plan_id_subscription_plans_id_fk" FOREIGN KEY ("plan_id") REFERENCES "subscription_plans"("id") ON DELETE no action ON UPDATE no action;
EXCEPTION
 WHEN duplicate_object THEN null;
END $$;

-- Вставляем базовые тарифные планы
INSERT INTO "subscription_plans" ("name", "description", "price", "duration_days", "features", "sort_order") 
VALUES 
  ('Базовый', 'Доступ к основным тестам', 99000, 30, '["basic_tests", "progress_tracking"]', 1),
  ('Премиум', 'Все тесты + аналитика', 199000, 30, '["all_tests", "progress_tracking", "detailed_analytics", "export_results"]', 2),
  ('Про', 'Максимальный функционал', 299000, 30, '["all_tests", "progress_tracking", "detailed_analytics", "export_results", "priority_support", "unlimited_attempts"]', 3)
ON CONFLICT (name) DO NOTHING;