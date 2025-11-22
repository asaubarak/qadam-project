import { useState } from "react";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { 
  Dialog, 
  DialogContent, 
  DialogDescription, 
  DialogHeader, 
  DialogTitle, 
  DialogTrigger 
} from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { 
  Form, 
  FormControl, 
  FormDescription,
  FormField, 
  FormItem, 
  FormLabel, 
  FormMessage 
} from "@/components/ui/form";
import { 
  Select, 
  SelectContent, 
  SelectItem, 
  SelectTrigger, 
  SelectValue 
} from "@/components/ui/select";
import { Checkbox } from "@/components/ui/checkbox";
import { Input } from "@/components/ui/input";
import { Progress } from "@/components/ui/progress";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Loader2, Download, FileText, FileSpreadsheet, AlertCircle } from "lucide-react";
import { useToast } from "@/hooks/use-toast";
import { apiRequest } from "@/lib/queryClient";
import { 
  exportOptionsSchema, 
  type ExportType, 
  type ExportFormat,
  type ExportOptions
} from "@shared/schema";
import { z } from "zod";

const formSchema = exportOptionsSchema.extend({
  type: z.enum(["USER_ANALYTICS", "TEST_REPORT", "RANKINGS", "PERIOD_SUMMARY"]),
  format: z.enum(["PDF", "EXCEL"]),
});

type FormValues = z.infer<typeof formSchema>;

interface ExportDialogProps {
  defaultType: ExportType;
  trigger?: React.ReactNode;
  title?: string;
  description?: string;
}

interface ExportJobStatus {
  status: "PENDING" | "IN_PROGRESS" | "COMPLETED" | "FAILED";
  progress: number;
  downloadUrl?: string;
  fileName?: string;
  fileSize?: number;
  error?: string;
}

export function ExportDialog({ 
  defaultType, 
  trigger,
  title = "Экспорт данных",
  description = "Выберите формат и настройки для экспорта"
}: ExportDialogProps) {
  const [open, setOpen] = useState(false);
  const [jobId, setJobId] = useState<string | null>(null);
  const [isPolling, setIsPolling] = useState(false);
  const { toast } = useToast();
  const queryClient = useQueryClient();

  const form = useForm<FormValues>({
    resolver: zodResolver(formSchema),
    defaultValues: {
      type: defaultType,
      format: "PDF",
      includeCharts: true,
      dateRange: undefined,
      subjects: [],
      columns: [],
    },
  });

  const watchedType = form.watch("type");
  const watchedFormat = form.watch("format");

  // Create export job mutation
  const createExportMutation = useMutation({
    mutationFn: async (values: FormValues) => {
      const { type, format, ...options } = values;
      const response = await apiRequest("POST", "/api/exports", { type, format, options });
      return (await response.json()) as { jobId: string };
    },
    onSuccess: (data) => {
      setJobId(data.jobId);
      setIsPolling(true);
      toast({
        title: "Экспорт запущен",
        description: "Ваш файл создается. Пожалуйста, подождите...",
      });
    },
    onError: (error: any) => {
      toast({
        title: "Ошибка",
        description: error?.message || "Не удалось создать экспорт",
        variant: "destructive",
      });
    },
  });

  // Poll job status
  const { data: jobStatus, isLoading: statusLoading } = useQuery<ExportJobStatus | null>({
    queryKey: ["/api/exports", jobId, "status"],
    queryFn: async () => {
      if (!jobId) return null;
      const response = await apiRequest("GET", `/api/exports/${jobId}/status`);
      return (await response.json()) as ExportJobStatus;
    },
    enabled: !!jobId && isPolling,
    refetchInterval: (query) => {
      const data = query.state.data as ExportJobStatus | null;
      if (data?.status === "COMPLETED" || data?.status === "FAILED") {
        setIsPolling(false);
        return false;
      }
      return 2000; // Poll every 2 seconds
    },
    refetchIntervalInBackground: true,
  });

  const handleDownload = async () => {
    if (!jobId || !jobStatus?.downloadUrl) return;

    try {
      const response = await fetch(jobStatus.downloadUrl);
      if (!response.ok) throw new Error("Ошибка загрузки");

      const blob = await response.blob();
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = jobStatus.fileName || "export";
      document.body.appendChild(a);
      a.click();
      window.URL.revokeObjectURL(url);
      document.body.removeChild(a);

      toast({
        title: "Успешно",
        description: "Файл скачан",
      });

      // Reset and close
      handleClose();
    } catch (error) {
      toast({
        title: "Ошибка",
        description: "Не удалось скачать файл",
        variant: "destructive",
      });
    }
  };

  const handleClose = () => {
    setOpen(false);
    setJobId(null);
    setIsPolling(false);
    form.reset();
  };

  const onSubmit = (values: FormValues) => {
    createExportMutation.mutate(values);
  };

  const getTypeLabel = (type: ExportType) => {
    switch (type) {
      case "USER_ANALYTICS": return "Аналитика пользователя";
      case "TEST_REPORT": return "Отчет по тестам";
      case "RANKINGS": return "Рейтинг пользователей";
      case "PERIOD_SUMMARY": return "Сводка за период";
    }
  };

  const formatBytes = (bytes: number) => {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  };

  // Show progress/completion dialog
  if (jobId && (isPolling || jobStatus)) {
    return (
      <Dialog open={open} onOpenChange={handleClose}>
        <DialogTrigger asChild>
          {trigger || (
            <Button variant="outline" data-testid="button-export">
              <Download className="w-4 h-4 mr-2" />
              Экспорт
            </Button>
          )}
        </DialogTrigger>
        <DialogContent className="sm:max-w-md" data-testid="dialog-export-progress">
          <DialogHeader>
            <DialogTitle>Экспорт данных</DialogTitle>
          </DialogHeader>
          
          {jobStatus?.status === "FAILED" && (
            <Alert variant="destructive">
              <AlertCircle className="h-4 w-4" />
              <AlertDescription>
                {jobStatus.error || "Произошла ошибка при создании экспорта"}
              </AlertDescription>
            </Alert>
          )}

          {jobStatus?.status === "COMPLETED" && (
            <div className="space-y-4">
              <Alert>
                <FileText className="h-4 w-4" />
                <AlertDescription>
                  Экспорт завершен! Файл готов к скачиванию.
                </AlertDescription>
              </Alert>
              
              <div className="flex items-center justify-between p-4 bg-muted rounded-lg">
                <div className="flex items-center space-x-3">
                  {watchedFormat === "PDF" ? (
                    <FileText className="w-8 h-8 text-red-500" />
                  ) : (
                    <FileSpreadsheet className="w-8 h-8 text-green-500" />
                  )}
                  <div>
                    <p className="text-sm font-medium" data-testid="text-filename">
                      {jobStatus.fileName}
                    </p>
                    <p className="text-xs text-muted-foreground">
                      {jobStatus.fileSize ? formatBytes(jobStatus.fileSize) : "Размер неизвестен"}
                    </p>
                  </div>
                </div>
                <Button onClick={handleDownload} data-testid="button-download">
                  <Download className="w-4 h-4 mr-2" />
                  Скачать
                </Button>
              </div>
            </div>
          )}

          {(jobStatus?.status === "PENDING" || jobStatus?.status === "IN_PROGRESS") && (
            <div className="space-y-4">
              <div className="text-center">
                <Loader2 className="w-8 h-8 animate-spin mx-auto mb-2" />
                <p className="text-sm text-muted-foreground">
                  {jobStatus.status === "PENDING" 
                    ? "Экспорт в очереди..." 
                    : "Создание файла..."}
                </p>
              </div>
              
              <div className="space-y-2">
                <div className="flex justify-between text-xs">
                  <span>Прогресс</span>
                  <span data-testid="text-progress">{jobStatus.progress}%</span>
                </div>
                <Progress value={jobStatus.progress} />
              </div>
            </div>
          )}

          <div className="flex justify-end">
            <Button variant="outline" onClick={handleClose}>
              {jobStatus?.status === "COMPLETED" ? "Закрыть" : "Отменить"}
            </Button>
          </div>
        </DialogContent>
      </Dialog>
    );
  }

  // Show configuration dialog
  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild>
        {trigger || (
          <Button variant="outline" data-testid="button-export">
            <Download className="w-4 h-4 mr-2" />
            Экспорт
          </Button>
        )}
      </DialogTrigger>
      <DialogContent className="sm:max-w-md" data-testid="dialog-export-config">
        <DialogHeader>
          <DialogTitle>{title}</DialogTitle>
          <DialogDescription>{description}</DialogDescription>
        </DialogHeader>
        
        <Form {...form}>
          <form onSubmit={form.handleSubmit(onSubmit)} className="space-y-4">
            <FormField
              control={form.control}
              name="type"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>Тип экспорта</FormLabel>
                  <Select onValueChange={field.onChange} defaultValue={field.value}>
                    <FormControl>
                      <SelectTrigger data-testid="select-type">
                        <SelectValue placeholder="Выберите тип" />
                      </SelectTrigger>
                    </FormControl>
                    <SelectContent>
                      <SelectItem value="USER_ANALYTICS">Аналитика пользователя</SelectItem>
                      <SelectItem value="TEST_REPORT">Отчет по тестам</SelectItem>
                      <SelectItem value="RANKINGS">Рейтинг пользователей</SelectItem>
                      <SelectItem value="PERIOD_SUMMARY">Сводка за период</SelectItem>
                    </SelectContent>
                  </Select>
                  <FormMessage />
                </FormItem>
              )}
            />

            <FormField
              control={form.control}
              name="format"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>Формат файла</FormLabel>
                  <Select onValueChange={field.onChange} defaultValue={field.value}>
                    <FormControl>
                      <SelectTrigger data-testid="select-format">
                        <SelectValue placeholder="Выберите формат" />
                      </SelectTrigger>
                    </FormControl>
                    <SelectContent>
                      <SelectItem value="PDF">PDF</SelectItem>
                      <SelectItem value="EXCEL">Excel (XLSX)</SelectItem>
                    </SelectContent>
                  </Select>
                  <FormMessage />
                </FormItem>
              )}
            />

            {watchedType === "PERIOD_SUMMARY" && (
              <div className="grid grid-cols-2 gap-4">
                <FormField
                  control={form.control}
                  name="dateRange.from"
                  render={({ field }) => (
                    <FormItem>
                      <FormLabel>Дата от</FormLabel>
                      <FormControl>
                        <Input 
                          type="date" 
                          {...field} 
                          data-testid="input-date-from"
                        />
                      </FormControl>
                      <FormMessage />
                    </FormItem>
                  )}
                />
                
                <FormField
                  control={form.control}
                  name="dateRange.to"
                  render={({ field }) => (
                    <FormItem>
                      <FormLabel>Дата до</FormLabel>
                      <FormControl>
                        <Input 
                          type="date" 
                          {...field}
                          data-testid="input-date-to"
                        />
                      </FormControl>
                      <FormMessage />
                    </FormItem>
                  )}
                />
              </div>
            )}

            <FormField
              control={form.control}
              name="includeCharts"
              render={({ field }) => (
                <FormItem className="flex flex-row items-start space-x-3 space-y-0">
                  <FormControl>
                    <Checkbox
                      checked={field.value}
                      onCheckedChange={field.onChange}
                      data-testid="checkbox-charts"
                    />
                  </FormControl>
                  <div className="space-y-1 leading-none">
                    <FormLabel>
                      Включить графики
                    </FormLabel>
                    <FormDescription>
                      Добавить диаграммы и графики в экспорт
                    </FormDescription>
                  </div>
                </FormItem>
              )}
            />

            <div className="flex justify-end space-x-2">
              <Button 
                type="button" 
                variant="outline" 
                onClick={() => setOpen(false)}
              >
                Отменить
              </Button>
              <Button 
                type="submit" 
                disabled={createExportMutation.isPending}
                data-testid="button-create-export"
              >
                {createExportMutation.isPending && (
                  <Loader2 className="w-4 h-4 mr-2 animate-spin" />
                )}
                Создать экспорт
              </Button>
            </div>
          </form>
        </Form>
      </DialogContent>
    </Dialog>
  );
}
