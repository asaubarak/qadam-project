import { useState, useEffect } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Skeleton } from "@/components/ui/skeleton";
import { useToast } from "@/hooks/use-toast";
import { apiRequest } from "@/lib/queryClient";

type Quote = {
  id: string;
  text: string;
  author: string;
  month: number;
  order: number;
};

export function SystemSettings() {
  const { toast } = useToast();
  const queryClient = useQueryClient();
  const [entDate, setEntDate] = useState("");
  const [selectedMonth, setSelectedMonth] = useState(new Date().getMonth() + 1);
  const [newQuoteText, setNewQuoteText] = useState("");
  const [newQuoteAuthor, setNewQuoteAuthor] = useState("");
  const [editingQuote, setEditingQuote] = useState<Quote | null>(null);

  // Fetch ENT date setting
  const { data: entDateSetting, isLoading } = useQuery<{key: string, value: string}>({
    queryKey: ["/api/settings/ent_exam_date"],
  });

  // Fetch quotes for selected month
  const { data: quotes = [], isLoading: quotesLoading } = useQuery<Quote[]>({
    queryKey: ["/api/quotes/month", selectedMonth],
  });

  // Update ENT date when loaded
  useEffect(() => {
    if (entDateSetting?.value) {
      // Convert ISO string to YYYY-MM-DD format for input
      const date = new Date(entDateSetting.value);
      setEntDate(date.toISOString().split('T')[0]);
    }
  }, [entDateSetting]);

  // Update setting mutation
  const updateSettingMutation = useMutation({
    mutationFn: async (value: string) => {
      const isoDate = new Date(value).toISOString();
      const res = await apiRequest("PUT", "/api/admin/settings/ent_exam_date", { value: isoDate });
      return await res.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/settings/ent_exam_date"] });
      toast({ title: "Успешно", description: "Дата ЕНТ обновлена" });
    },
    onError: () => {
      toast({ title: "Ошибка", description: "Не удалось обновить дату ЕНТ", variant: "destructive" });
    },
  });

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!entDate) {
      toast({ title: "Ошибка", description: "Выберите дату", variant: "destructive" });
      return;
    }
    updateSettingMutation.mutate(entDate);
  };

  // Create quote mutation
  const createQuoteMutation = useMutation({
    mutationFn: async (data: { text: string; author: string; month: number }) => {
      const res = await apiRequest("POST", "/api/admin/quotes", data);
      return await res.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/quotes/month", selectedMonth] });
      toast({ title: "Успешно", description: "Цитата добавлена" });
      setNewQuoteText("");
      setNewQuoteAuthor("");
    },
    onError: () => {
      toast({ title: "Ошибка", description: "Не удалось добавить цитату", variant: "destructive" });
    },
  });

  // Update quote mutation
  const updateQuoteMutation = useMutation({
    mutationFn: async (data: { id: string; text: string; author: string; month: number }) => {
      const res = await apiRequest("PUT", `/api/admin/quotes/${data.id}`, {
        text: data.text,
        author: data.author,
        month: data.month,
      });
      return await res.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/quotes/month", selectedMonth] });
      toast({ title: "Успешно", description: "Цитата обновлена" });
      setEditingQuote(null);
    },
    onError: () => {
      toast({ title: "Ошибка", description: "Не удалось обновить цитату", variant: "destructive" });
    },
  });

  // Delete quote mutation
  const deleteQuoteMutation = useMutation({
    mutationFn: async (id: string) => {
      await apiRequest("DELETE", `/api/admin/quotes/${id}`);
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/quotes/month", selectedMonth] });
      toast({ title: "Успешно", description: "Цитата удалена" });
    },
    onError: () => {
      toast({ title: "Ошибка", description: "Не удалось удалить цитату", variant: "destructive" });
    },
  });

  const handleAddQuote = (e: React.FormEvent) => {
    e.preventDefault();
    if (!newQuoteText.trim() || !newQuoteAuthor.trim()) {
      toast({ title: "Ошибка", description: "Заполните все поля", variant: "destructive" });
      return;
    }
    createQuoteMutation.mutate({ text: newQuoteText, author: newQuoteAuthor, month: selectedMonth });
  };

  const handleUpdateQuote = (e: React.FormEvent) => {
    e.preventDefault();
    if (!editingQuote) return;
    updateQuoteMutation.mutate(editingQuote);
  };

  const months = [
    "Январь", "Февраль", "Март", "Апрель", "Май", "Июнь",
    "Июль", "Август", "Сентябрь", "Октябрь", "Ноябрь", "Декабрь"
  ];

  if (isLoading) {
    return (
      <Card>
        <CardHeader>
          <CardTitle>Системные настройки</CardTitle>
        </CardHeader>
        <CardContent>
          <Skeleton className="h-32 w-full" />
        </CardContent>
      </Card>
    );
  }

  return (
    <div className="space-y-6">
      {/* ENT Date Settings */}
      <Card>
        <CardHeader>
          <CardTitle>Дата ЕНТ</CardTitle>
        </CardHeader>
        <CardContent className="space-y-6">
          <form onSubmit={handleSubmit} className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="ent-date">Дата экзамена</Label>
              <Input
                id="ent-date"
                type="date"
                value={entDate}
                onChange={(e) => setEntDate(e.target.value)}
                required
                data-testid="input-ent-date"
              />
              <p className="text-sm text-muted-foreground">
                Эта дата используется для обратного отсчета на странице вариантов
              </p>
            </div>
            
            <Button 
              type="submit" 
              disabled={updateSettingMutation.isPending}
              data-testid="button-save-ent-date"
            >
              {updateSettingMutation.isPending ? "Сохранение..." : "Сохранить"}
            </Button>
          </form>

          {entDateSetting && (
            <div className="pt-4 border-t">
              <div className="text-sm text-muted-foreground">
                <p>Текущая дата: <strong>{new Date(entDateSetting.value).toLocaleDateString('ru-RU', { 
                  year: 'numeric', 
                  month: 'long', 
                  day: 'numeric' 
                })}</strong></p>
                <p className="mt-2">
                  До экзамена осталось: <strong>{Math.ceil((new Date(entDateSetting.value).getTime() - Date.now()) / (1000 * 60 * 60 * 24))} дней</strong>
                </p>
              </div>
            </div>
          )}
        </CardContent>
      </Card>

      {/* Quotes Management */}
      <Card>
        <CardHeader>
          <CardTitle>Управление цитатами</CardTitle>
        </CardHeader>
        <CardContent className="space-y-6">
          {/* Month selector */}
          <div className="space-y-2">
            <Label htmlFor="month-select">Выберите месяц</Label>
            <select
              id="month-select"
              className="w-full p-2 border rounded-md"
              value={selectedMonth}
              onChange={(e) => setSelectedMonth(parseInt(e.target.value))}
            >
              {months.map((month, index) => (
                <option key={index + 1} value={index + 1}>
                  {month}
                </option>
              ))}
            </select>
            <p className="text-sm text-muted-foreground">
              Цитаты показываются по очереди каждый день месяца
            </p>
          </div>

          {/* Add new quote form */}
          <form onSubmit={handleAddQuote} className="space-y-4 border-t pt-4">
            <h3 className="font-semibold">Добавить новую цитату</h3>
            <div className="space-y-2">
              <Label htmlFor="quote-text">Текст цитаты</Label>
              <Input
                id="quote-text"
                placeholder="Введите текст цитаты"
                value={newQuoteText}
                onChange={(e) => setNewQuoteText(e.target.value)}
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="quote-author">Автор</Label>
              <Input
                id="quote-author"
                placeholder="Введите имя автора"
                value={newQuoteAuthor}
                onChange={(e) => setNewQuoteAuthor(e.target.value)}
              />
            </div>
            <Button type="submit" disabled={createQuoteMutation.isPending}>
              {createQuoteMutation.isPending ? "Добавление..." : "Добавить цитату"}
            </Button>
          </form>

          {/* Quotes list */}
          <div className="space-y-4 border-t pt-4">
            <h3 className="font-semibold">
              Цитаты для {months[selectedMonth - 1]} ({quotes.length})
            </h3>
            
            {quotesLoading ? (
              <Skeleton className="h-32 w-full" />
            ) : quotes.length === 0 ? (
              <p className="text-sm text-muted-foreground">Нет цитат для этого месяца</p>
            ) : (
              <div className="space-y-3">
                {quotes.map((quote, index) => (
                  <Card key={quote.id} className="border">
                    <CardContent className="p-4">
                      {editingQuote?.id === quote.id ? (
                        <form onSubmit={handleUpdateQuote} className="space-y-3">
                          <Input
                            value={editingQuote.text}
                            onChange={(e) => setEditingQuote({ ...editingQuote, text: e.target.value })}
                          />
                          <Input
                            value={editingQuote.author}
                            onChange={(e) => setEditingQuote({ ...editingQuote, author: e.target.value })}
                          />
                          <div className="flex gap-2">
                            <Button type="submit" size="sm" disabled={updateQuoteMutation.isPending}>
                              Сохранить
                            </Button>
                            <Button
                              type="button"
                              size="sm"
                              variant="outline"
                              onClick={() => setEditingQuote(null)}
                            >
                              Отмена
                            </Button>
                          </div>
                        </form>
                      ) : (
                        <div>
                          <div className="flex items-start justify-between mb-2">
                            <div className="flex-1">
                              <p className="text-sm italic">"{quote.text}"</p>
                              <p className="text-xs text-muted-foreground mt-1">— {quote.author}</p>
                            </div>
                            <div className="flex gap-2 ml-4">
                              <Button
                                size="sm"
                                variant="outline"
                                onClick={() => setEditingQuote(quote)}
                              >
                                <i className="fas fa-edit"></i>
                              </Button>
                              <Button
                                size="sm"
                                variant="destructive"
                                onClick={() => deleteQuoteMutation.mutate(quote.id)}
                                disabled={deleteQuoteMutation.isPending}
                              >
                                <i className="fas fa-trash"></i>
                              </Button>
                            </div>
                          </div>
                          <p className="text-xs text-muted-foreground">
                            День показа: {index + 1} число месяца (и далее по циклу)
                          </p>
                        </div>
                      )}
                    </CardContent>
                  </Card>
                ))}
              </div>
            )}
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
