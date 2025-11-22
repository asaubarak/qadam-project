import { useState, useEffect, useRef, useMemo, useCallback } from "react";
import { useQuery, useMutation } from "@tanstack/react-query";
import { useRoute, useLocation } from "wouter";
import { useAuth } from "@/hooks/use-auth";
import { useRenderDebug } from "@/utils/render-debug";
// Header intentionally not rendered on test page to avoid navigation during a running test
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { Badge } from "@/components/ui/badge";
import { Dialog, DialogContent } from "@/components/ui/dialog";
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog";
import TestToolsModal from "@/components/test-tools-modal";
// Proctoring removed
import { queryClient } from "@/lib/queryClient";
import { apiRequest } from "@/lib/queryClient";
import { useToast } from "@/hooks/use-toast";
import { useOfflineSync } from "@/hooks/use-offline-sync";
import NetworkStatus from "@/components/network-status";
import MobileTestNavigation from "@/components/mobile-test-navigation";
import { useIsMobile } from "@/hooks/use-mobile";
import type { Variant, Block } from "@shared/schema";
import type { ActiveTest } from "@/lib/offline-db";

interface TestQuestion {
  id: string;
  text: string;
  imageUrl?: string; // URL изображения вопроса
  solutionImageUrl?: string; // URL изображения решения (показывается после теста)
  answers: Array<{
    id: string;
    text: string;
    isCorrect?: boolean; // Добавляем поле для режима просмотра
  }>;
}

interface TestSubject {
  subject: {
    id: string;
    name: string;
  };
  questions: TestQuestion[];
}

interface TestData {
  variant: Variant & { block: Block };
  testData: TestSubject[];
}

export default function TestPage() {
  const [match, params] = useRoute("/test/:variantId");
  const [publicMatch, publicParams] = useRoute("/public-test/:variantId");
  const [, setLocation] = useLocation();
  const { user } = useAuth();
  const { toast } = useToast();
  const { syncStatus, saveDraftTest, saveCompletedTest, getOfflineTest } = useOfflineSync();
  const isMobile = useIsMobile();
  const variantId = params?.variantId || publicParams?.variantId;
  const isPublicTest = !!publicMatch;

  // Get state from location (review mode) - вычисляем ОДИН РАЗ при монтировании
  const { isReviewMode, reviewTestData, reviewUserAnswers } = useMemo(() => {
    const urlParams = new URLSearchParams(window.location.search);
    const locationState = history.state as any;
    const reviewMode = locationState?.review === true || urlParams.get('review') === 'true';
    
    return {
      isReviewMode: reviewMode,
      reviewTestData: locationState?.testData,
      reviewUserAnswers: locationState?.userAnswers
    };
  }, []);

  // Упрощенная проверка режима просмотра

  const [currentQuestionIndex, setCurrentQuestionIndex] = useState(0);
  const [userAnswers, setUserAnswers] = useState<Record<string, string | string[]>>(
    isReviewMode ? (reviewUserAnswers || {}) : {}
  );
  const [showCalculator, setShowCalculator] = useState(false);
  const [showPeriodicTable, setShowPeriodicTable] = useState(false);
  const [timeLeft, setTimeLeft] = useState(240 * 60); // 240 minutes in seconds
  const [isOfflineMode, setIsOfflineMode] = useState(false);
  const [testStartTime] = useState(Date.now());
  const [imageModalOpen, setImageModalOpen] = useState(false);
  const [selectedImage, setSelectedImage] = useState<string | null>(null);
  const [showSubmitDialog, setShowSubmitDialog] = useState(false);

  // Мемоизированные callback для управления модальными окнами
  const handleCloseCalculator = useCallback(() => {
    setShowCalculator(false);
  }, []);
  
  const handleClosePeriodicTable = useCallback(() => {
    setShowPeriodicTable(false);
  }, []);

  const handleOpenCalculator = useCallback(() => {
    setShowCalculator(true);
  }, []);

  const handleOpenPeriodicTable = useCallback(() => {
    setShowPeriodicTable(true);
  }, []);

  // Small helper: numeric pagination (simple)
  function Pagination({ total, current, onChange }: { total: number; current: number; onChange: (i: number) => void }) {
    const windowSize = 7; // number of page buttons to show in pager window
    if (total <= 1) return null;

    const half = Math.floor(windowSize / 2);
    let start = Math.max(0, current - half);
    let end = Math.min(total, start + windowSize);
    if (end - start < windowSize) {
      start = Math.max(0, end - windowSize);
    }

    const pages: number[] = [];
    for (let i = start; i < end; i++) pages.push(i);

    const showLeftEllipsis = start > 1;
    const showRightEllipsis = end < total - 1;

    return (
      <div className="flex items-center gap-2">
        {/* first page if not in window */}
        {start > 0 && (
          <button onClick={() => onChange(0)} className={`px-2 py-1 rounded ${0 === current ? 'bg-accent text-white' : 'bg-transparent border'}`}>1</button>
        )}
        {showLeftEllipsis && <span className="px-2">...</span>}
        {pages.map(p => (
          <button
            key={p}
            onClick={() => onChange(p)}
            className={`px-2 py-1 rounded ${p === current ? 'bg-accent text-white' : 'bg-transparent border'}`}
          >{p+1}</button>
        ))}
        {showRightEllipsis && <span className="px-2">...</span>}
        {end < total && (
          <button onClick={() => onChange(total - 1)} className={`px-2 py-1 rounded ${total - 1 === current ? 'bg-accent text-white' : 'bg-transparent border'}`}>{total}</button>
        )}
      </div>
    );
  }

  // Clear previous test results when starting new test
  useEffect(() => {
    if (!isReviewMode && variantId) {
      sessionStorage.removeItem('testResultData');
    }
  }, [variantId, isReviewMode]);

  // Timer ticking effect: decrement timeLeft every second
  const handleTimeUpRef = useRef<() => void>();
  const timerRef = useRef<NodeJS.Timeout | null>(null);
  const timerStartedRef = useRef(false);
  
  useEffect(() => {
    if (timerStartedRef.current) return;
    if (isReviewMode) return;
    
    timerStartedRef.current = true;
    
    timerRef.current = setInterval(() => {
      setTimeLeft(prev => {
        const newValue = prev <= 1 ? 0 : prev - 1;
        
        if (newValue === 0 && timerRef.current) {
          clearInterval(timerRef.current);
          timerRef.current = null;
          setTimeout(() => handleTimeUpRef.current?.(), 0);
        }
        
        return newValue;
      });
    }, 1000);
    
    return () => {
      if (timerRef.current) {
        clearInterval(timerRef.current);
        timerRef.current = null;
      }
    };
  }, [isReviewMode]);

  // pagination window size intentionally unified across devices

  // Proctoring removed

  const { data: testData, isLoading } = useQuery<TestData>({
    queryKey: [isPublicTest ? "/api/public/variants" : "/api/variants", variantId, "test"],
    enabled: !!variantId && !isReviewMode,
    initialData: undefined, // НЕ используем initialData в режиме просмотра
  });

  // В режиме просмотра используем ТОЛЬКО данные из reviewTestData (API)
  const finalTestData = useMemo(() => {
    return isReviewMode ? reviewTestData : testData;
  }, [isReviewMode, reviewTestData, testData]);

  // МЕМОИЗАЦИЯ: вычисляем allQuestions только когда finalTestData меняется
  const allQuestions = useMemo(() => {
    if (!finalTestData || !finalTestData.testData) return [];
    return finalTestData.testData.flatMap(subject => 
      subject.questions.map(q => ({ ...q, subjectName: subject.subject.name }))
    );
  }, [finalTestData]);

  // Proctoring removed

  const submitTestMutation = useMutation({
    mutationFn: async (answers: Record<string, string | string[]>) => {
  // Proctoring removed: no action needed here.

      try {
        // Try online submission first
        if (syncStatus.isOnline) {
          const endpoint = isPublicTest ? "/api/public/test-results" : "/api/test-results";
          const res = await apiRequest("POST", endpoint, {
            variantId,
            answers,
            timeSpent: (240 * 60) - timeLeft,
          });
          return await res.json();
        } else {
          throw new Error('Offline mode');
        }
      } catch (error) {
        // For public tests, don't save offline - just show error
        if (isPublicTest) {
          throw error;
        }
        
        // Save for offline sync if online submission fails (only for authenticated users)
        const offlineResult = {
          id: `result-${variantId}-${user?.id}-${Date.now()}`,
          testId: `${variantId}-${user?.id}`,
          variantId: variantId!,
          answers,
          timeSpent: (240 * 60) - timeLeft,
          completedAt: Date.now(),
          syncStatus: 'pending' as const,
          syncAttempts: 0
        };
        
        await saveCompletedTest(offlineResult);
        
        return {
          offline: true,
          message: 'Тест сохранен для синхронизации'
        };
      }
    },
    onSuccess: (result) => {
      if (result.offline) {
        toast({
          title: "Тест завершен",
          description: "Результаты будут синхронизированы при восстановлении связи",
        });
      } else {
        const successMessage = result.isGuestResult 
          ? "Результаты готовы! Зарегистрируйтесь для сохранения прогресса" 
          : "Результаты успешно сохранены";
          
        toast({
          title: "Тест завершен",
          description: successMessage,
        });
        
        if (!result.isGuestResult) {
          queryClient.invalidateQueries({ queryKey: ["/api/profile"] });
        }
      }
      
      // Clean up offline data
      localStorage.removeItem(`test_${variantId}_answers`);
      
      // For guest results, show results directly, for authenticated users navigate to results page
      if (result.isGuestResult) {
        setTimeout(() => {
          setLocation("/", { 
            state: { 
              guestResult: result,
              testData: finalTestData, 
              userAnswers,
              showResults: true
            } 
          });
        }, 0);
      } else {
        // Сохраняем данные в sessionStorage для страницы результатов
        // Используем reviewTestData из ответа сервера (содержит флаги isCorrect)
        const responseData = result as any;
        const reviewTestData = responseData.testData || finalTestData;
        const reviewUserAnswers = responseData.userAnswers || userAnswers;
        
        sessionStorage.setItem('testResultData', JSON.stringify({ 
          result: responseData.result || result, 
          testData: reviewTestData, 
          userAnswers: reviewUserAnswers 
        }));
        setLocation("/results");
      }
    },
    onError: () => {
      toast({
        title: "Ошибка",
        description: "Не удалось сохранить результаты теста",
        variant: "destructive",
      });
    },
  });

  // Auto-save answers every 30 seconds (offline-first) - НЕ в режиме просмотра
  // Используем refs чтобы избежать пересоздания useEffect при изменении данных
  const userAnswersRef = useRef(userAnswers);
  const timeLeftRef = useRef(timeLeft);
  const testDataRef = useRef(testData);
  const finalTestDataRef = useRef(finalTestData);
  const getOfflineTestRef = useRef(getOfflineTest);
  const toastRef = useRef(toast);
  
  // Обновляем refs после каждого рендера (это безопасно, не вызывает ре-рендер)
  // ВРЕМЕННО ОТКЛЮЧЕНО для отладки
  /*
  useEffect(() => {
    if (renderCount.current > 10) {
      console.log('📌 Refs updated');
    }
    userAnswersRef.current = userAnswers;
    timeLeftRef.current = timeLeft;
    testDataRef.current = testData;
    finalTestDataRef.current = finalTestData;
    getOfflineTestRef.current = getOfflineTest;
    toastRef.current = toast;
  });
  */
  
  // Обновляем refs напрямую в render phase (это безопасно)
  userAnswersRef.current = userAnswers;
  timeLeftRef.current = timeLeft;
  testDataRef.current = testData;
  finalTestDataRef.current = finalTestData;
  getOfflineTestRef.current = getOfflineTest;
  toastRef.current = toast;
  
  useEffect(() => {
    if (isReviewMode) {
      return; // Не сохраняем в режиме просмотра
    }
    
    const interval = setInterval(async () => {
      const currentAnswers = userAnswersRef.current;
      const currentTestData = testDataRef.current;
      const currentFinalTestData = finalTestDataRef.current;
      const currentTimeLeft = timeLeftRef.current;
      
      if (variantId && currentTestData && Object.keys(currentAnswers).length > 0) {
        try {
          const activeTest: ActiveTest = {
            id: `${variantId}-${user?.id}`,
            variantId,
            variant: {
              ...currentTestData.variant,
              block: currentFinalTestData.variant.block || {
                hasCalculator: false,
                hasPeriodicTable: false,
              }
            },
            testData: currentFinalTestData.testData,
            userAnswers: currentAnswers,
            startedAt: testStartTime,
            lastSavedAt: Date.now(),
            timeSpent: (240 * 60) - currentTimeLeft,
            isCompleted: false,
            syncStatus: 'pending',
            syncAttempts: 0
          };
          
          await saveDraftTest(activeTest);
          
          // Fallback to localStorage
          localStorage.setItem(`test_${variantId}_answers`, JSON.stringify(currentAnswers));
        } catch (error) {
          console.error('Failed to save test draft:', error);
          // Fallback to localStorage only
          localStorage.setItem(`test_${variantId}_answers`, JSON.stringify(currentAnswers));
        }
      }
    }, 30000);

    return () => clearInterval(interval);
  }, [variantId, user?.id, testStartTime, saveDraftTest, isReviewMode]);

  // Load saved answers on component mount (offline-first) - НЕ в режиме просмотра
  useEffect(() => {
    if (isReviewMode) {
      return; // Не загружаем сохраненные данные в режиме просмотра
    }
    
    if (variantId && user?.id) {
      const loadSavedTest = async () => {
        try {
          // Try offline database first - используем ref чтобы не зависеть от getOfflineTest
          const offlineTest = await getOfflineTestRef.current(`${variantId}-${user.id}`);
          if (offlineTest) {
            setUserAnswers(offlineTest.userAnswers);
            setTimeLeft(Math.max(0, 240 * 60 - offlineTest.timeSpent));
            setIsOfflineMode(true);
            
            toastRef.current({
              title: "Тест восстановлен",
              description: "Продолжаем с сохраненного места",
            });
            return;
          }
          
          // Fallback to localStorage
          const savedAnswers = localStorage.getItem(`test_${variantId}_answers`);
          if (savedAnswers) {
            setUserAnswers(JSON.parse(savedAnswers));
          }
        } catch (error) {
          console.error('Failed to load saved test:', error);
          // Fallback to localStorage
          const savedAnswers = localStorage.getItem(`test_${variantId}_answers`);
          if (savedAnswers) {
            setUserAnswers(JSON.parse(savedAnswers));
          }
        }
      };
      
      loadSavedTest();
    }
  }, [variantId, user?.id, isReviewMode]);

  // Определяем handleTimeUp ДО любых условных return (правило хуков)
  const handleTimeUp = useCallback(() => {
    toast({
      title: "Время вышло",
      description: "Тест автоматически завершен",
    });
    submitTestMutation.mutate(userAnswers);
  }, [toast, submitTestMutation, userAnswers]);
  
  // Обновляем ref при изменении handleTimeUp
  useEffect(() => {
    handleTimeUpRef.current = handleTimeUp;
  }, [handleTimeUp]);
  
  // Redirect to home if no match - ВАЖНО: в useEffect чтобы не вызывать setState в render phase!
  useEffect(() => {
    if ((!match && !publicMatch) || !variantId) {
      setLocation("/");
    }
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [match, publicMatch, variantId]); // НЕ включаем setLocation в dependencies!

  if ((!match && !publicMatch) || !variantId) {
    return null;
  }

  if (isLoading) {
    return (
      <div className="min-h-screen bg-background">
        <main className="container mx-auto px-4 lg:px-6 py-8">
          <div className="space-y-6">
            <Skeleton className="h-20 w-full" />
            <div className="grid grid-cols-1 lg:grid-cols-4 gap-6">
              <div className="lg:col-span-3">
                <Skeleton className="h-96 w-full" />
              </div>
              <div className="space-y-4">
                <Skeleton className="h-64 w-full" />
                <Skeleton className="h-32 w-full" />
              </div>
            </div>
          </div>
        </main>
      </div>
    );
  }

  // В режиме просмотра проверяем только базовые поля (variant.block отсутствует в API)
  const hasRequiredData = isReviewMode 
    ? !!(finalTestData && finalTestData.variant && finalTestData.testData)
    : !!(finalTestData && finalTestData.variant && finalTestData.variant.block && finalTestData.testData);
  
  if (!hasRequiredData) {

    
    return (
      <div className="min-h-screen bg-background">
        <main className="container mx-auto px-4 lg:px-6 py-8">
          <div className="text-center">
            <h1 className="text-2xl font-bold text-foreground mb-4">Тест не найден</h1>
            <p className="text-muted-foreground mb-4">
              {isReviewMode ? 'Ошибка в режиме просмотра результатов' : 'Ошибка загрузки теста'}
            </p>
            <Button onClick={() => setLocation("/")} data-testid="button-back-home">
              Вернуться на главную
            </Button>
          </div>
        </main>
      </div>
    );
  }

  // Краткое логирование данных в режиме просмотра
  if (isReviewMode && testData) {
  }

  const currentQuestion = allQuestions[currentQuestionIndex];
  const progress = ((currentQuestionIndex + 1) / allQuestions.length) * 100;

  // Вычисляем номер вопроса внутри предмета
  const getQuestionNumberInSubject = (globalIndex: number) => {
    let questionCount = 0;
    let currentSubjectIndex = 0;
    
    for (let i = 0; i < finalTestData.testData.length; i++) {
      const subjectQuestionCount = finalTestData.testData[i].questions.length;
      
      if (globalIndex < questionCount + subjectQuestionCount) {
        return {
          questionNumber: globalIndex - questionCount + 1,
          subjectIndex: i,
          subjectName: finalTestData.testData[i].subject.name
        };
      }
      
      questionCount += subjectQuestionCount;
    }
    
    return { questionNumber: 1, subjectIndex: 0, subjectName: '' };
  };

  const currentQuestionInfo = getQuestionNumberInSubject(currentQuestionIndex);

  const handleAnswerSelect = (questionId: string, answerId: string) => {
    const question = allQuestions.find(q => q.id === questionId);
    if (!question) return;
    
    const isMultipleChoice = question.answers.length === 8;
    
    if (isMultipleChoice) {
      // Multiple choice: toggle answer in array
      setUserAnswers(prev => {
        const current = prev[questionId];
        const currentArray = Array.isArray(current) ? current : [];
        
        if (currentArray.includes(answerId)) {
          // Remove if already selected
          return {
            ...prev,
            [questionId]: currentArray.filter(id => id !== answerId),
          };
        } else {
          // Add if not selected
          return {
            ...prev,
            [questionId]: [...currentArray, answerId],
          };
        }
      });
    } else {
      // Single choice: replace with new answer
      setUserAnswers(prev => ({
        ...prev,
        [questionId]: answerId,
      }));
    }
  };

  const handleSubmitTest = () => {
    setShowSubmitDialog(true);
  };

  const confirmSubmitTest = () => {
    setShowSubmitDialog(false);
    submitTestMutation.mutate(userAnswers);
  };

  // Mobile view with MobileTestNavigation
  if (isMobile) {
    return (
        <div className="min-h-screen bg-background">
          <MobileTestNavigation
            questions={allQuestions.map(q => ({
              id: q.id,
              text: q.text,
              answers: q.answers,
              subjectName: finalTestData.testData.find(td => td.questions.some(tq => tq.id === q.id))?.subject.name || ""
            }))}
            currentIndex={currentQuestionIndex}
            userAnswers={userAnswers}
            onQuestionChange={setCurrentQuestionIndex}
            onAnswerSelect={isReviewMode ? (() => {}) : handleAnswerSelect}
            onSubmit={isReviewMode ? (() => setLocation("/results")) : handleSubmitTest}
            isSubmitting={submitTestMutation.isPending}
            timeLeft={isReviewMode ? 0 : timeLeft}
            isReviewMode={isReviewMode}
          />

        </div>
    );
  }

  // Desktop view - возвращаем JSX напрямую без промежуточного компонента
  return (
    <div className="min-h-screen bg-background">
      <main className="w-full mx-auto px-0 py-8">
        {/* Test Header */}
          <div className="mb-6 px-4 lg:px-6">
          <div className="flex flex-col md:flex-row md:items-center md:justify-between mb-4 space-y-3 md:space-y-0">
            <div>
              <div className="flex items-center gap-3 mb-2">
                <h1 className="text-xl md:text-2xl font-bold text-foreground line-clamp-2">
                  {finalTestData.variant.block?.name || 'Тест'} - {finalTestData.variant.name}
                </h1>
                {isReviewMode && (
                  <Badge variant="outline" className="bg-blue-50 text-blue-500 border-blue-500">
                    <i className="fas fa-eye mr-1"></i>
                    Қарау режимі
                  </Badge>
                )}
              </div>
              {isOfflineMode && (
                <div className="flex items-center mt-2">
                  <NetworkStatus showDetails={true} className="text-sm" />
                </div>
              )}
            </div>
            <div className="flex items-center space-x-4">
              <NetworkStatus className="md:hidden" />
              {/* Таймер справа (только для ПК и режима тестирования) */}
              {!isReviewMode && (
                <div className="hidden lg:flex items-center gap-2 bg-card border rounded-lg px-4 py-2 shadow-sm">
                  <i className="fas fa-clock text-blue-500"></i>
                  <span className="text-lg font-mono font-bold text-foreground">
                    {Math.floor(timeLeft / 60)}:{(timeLeft % 60).toString().padStart(2, '0')}
                  </span>
                </div>
              )}
            </div>
          </div>
        </div>

  <div className="grid grid-cols-1 lg:grid-cols-4 gap-4 lg:gap-6 px-4 lg:px-0">
          {/* Left subject menu (1 of 4) */}
          <div className="lg:col-span-1 lg:pl-0">
            <Card>
              <CardHeader>
                <div className="flex items-center justify-between">
                  <CardTitle className="text-lg">Предметы</CardTitle>
                  <div className="flex items-center space-x-2">
                    {!isReviewMode && finalTestData?.variant?.block?.hasCalculator === true && (
                      <Button
                        variant="ghost"
                        size="sm"
                        onClick={handleOpenCalculator}
                        data-testid="button-calculator-mini"
                        className="h-6 w-6 p-2 min-h-[32px] min-w-[32px]"
                      >
                        <i className="fas fa-calculator text-xs"></i>
                      </Button>
                    )}
                    {!isReviewMode && finalTestData?.variant?.block?.hasPeriodicTable === true && (
                      <Button
                        variant="ghost"
                        size="sm"
                        onClick={handleOpenPeriodicTable}
                        data-testid="button-periodic-table-mini"
                        className="h-6 w-6 p-2 min-h-[32px] min-w-[32px]"
                      >
                        <i className="fas fa-table text-xs"></i>
                      </Button>
                    )}
                  </div>
                </div>
              </CardHeader>
              <CardContent className="space-y-2">
                {finalTestData.testData.map((s, si) => {
                  const unanswered = s.questions.filter(q => !userAnswers[q.id]).length;
                  return (
                    <button
                      key={s.subject.id}
                      className={`w-full text-left p-2 rounded-lg flex items-center justify-between hover:bg-muted/50 ${finalTestData.testData.findIndex(x=>x.subject.id===s.subject.id) === si ? 'bg-muted' : ''}`}
                      onClick={() => {
                        // jump to first question of this subject
                        const qIndex = allQuestions.findIndex(q => q.subjectName === s.subject.name);
                        if (qIndex >= 0) setCurrentQuestionIndex(qIndex);
                      }}
                    >
                      <span>{s.subject.name}</span>
                      <Badge>{unanswered}</Badge>
                    </button>
                  );
                })}
              </CardContent>
            </Card>


          </div>

          {/* Question Content (center - 3 of 4 columns = 75%) */}
          <div className="lg:col-span-3 lg:pr-6">
            <Card>
              <CardHeader>
                <div className="flex items-center justify-between">
                  <CardTitle>{currentQuestionInfo.subjectName} - Вопрос {currentQuestionInfo.questionNumber}</CardTitle>
                  <Badge variant="secondary">{currentQuestion?.subjectName}</Badge>
                </div>
              </CardHeader>
              <CardContent className="space-y-6">
                <div className={`flex gap-6 ${currentQuestion?.imageUrl ? 'items-start' : ''}`}>
                  {/* Текст вопроса */}
                  <div className="flex-1">
                    <div className="text-lg text-foreground leading-relaxed">
                      {currentQuestion?.text}
                    </div>
                    
                    {/* Multiple choice hint */}
                    {currentQuestion?.answers.length === 8 && !isReviewMode && (
                      <div className="mt-2 text-sm text-muted-foreground italic">
                        Выберите 3 правильных ответа (2 балла за полностью верный ответ)
                      </div>
                    )}
                  </div>
                  
                  {/* Изображение вопроса справа */}
                  {currentQuestion?.imageUrl && (
                    <div 
                      className="flex-shrink-0 cursor-pointer transition-transform hover:scale-105"
                      onClick={() => {
                        setSelectedImage(currentQuestion.imageUrl!);
                        setImageModalOpen(true);
                      }}
                    >
                      <img 
                        src={currentQuestion.imageUrl} 
                        alt="Изображение к вопросу" 
                        className="w-[400px] h-[400px] object-contain rounded-lg border shadow-sm bg-muted/30"
                      />
                    </div>
                  )}
                </div>
                
                <div className="space-y-3">
                  {currentQuestion?.answers.map((answer, index) => {
                    // Determine if this is multiple choice (8 answers) or single choice (5 answers)
                    const isMultipleChoice = currentQuestion.answers.length === 8;
                    
                    // Определяем, выбран ли этот ответ
                    const userAnswer = userAnswers[currentQuestion.id];
                    const isSelected = isMultipleChoice 
                      ? Array.isArray(userAnswer) && userAnswer.includes(answer.id)
                      : userAnswer === answer.id;
                    
                    // Определяем стиль для режима просмотра результатов
                    const getAnswerStyle = () => {
                      // Режим тестирования (не просмотр результатов)
                      if (!isReviewMode) {
                        if (isSelected) {
                          // Выбранный ответ - синяя подсветка
                          return "w-full p-4 rounded-lg border-2 border-blue-500 bg-blue-50 text-blue-500 cursor-pointer transition-colors text-left flex items-start gap-3";
                        }
                        // Обычный невыбранный ответ
                        return "w-full p-4 rounded-lg border border-border hover:bg-muted/50 cursor-pointer transition-colors text-left flex items-start gap-3";
                      }
                      
                      const isUserAnswer = isMultipleChoice
                        ? Array.isArray(userAnswer) && userAnswer.includes(answer.id)
                        : userAnswer === answer.id;
                      const isCorrectAnswer = answer.isCorrect === true;
                      
                      if (isUserAnswer && isCorrectAnswer) {
                        // Мой правильный ответ - синий
                        return "w-full p-4 rounded-lg border-2 border-blue-500 bg-blue-50 text-blue-500 transition-colors text-left flex items-start gap-3";
                      } else if (isUserAnswer && !isCorrectAnswer) {
                        // Мой неправильный ответ - красный  
                        return "w-full p-4 rounded-lg border-2 border-red-500 bg-red-50 text-red-800 transition-colors text-left flex items-start gap-3";
                      } else if (!isUserAnswer && isCorrectAnswer) {
                        // Правильный ответ (где я не отвечал) - зеленый
                        return "w-full p-4 rounded-lg border-2 border-green-500 bg-green-50 text-green-800 transition-colors text-left flex items-start gap-3";
                      } else {
                        // Неправильный ответ (где я не отвечал) - обычный серый
                        return "w-full p-4 rounded-lg border border-border bg-muted/20 transition-colors opacity-60 text-left flex items-start gap-3";
                      }
                    };

                    return (
                      <button
                        key={answer.id}
                        type="button"
                        onClick={() => !isReviewMode && handleAnswerSelect(currentQuestion.id, answer.id)}
                        className={getAnswerStyle()}
                        disabled={isReviewMode}
                        data-testid={`button-answer-${answer.id}`}
                      >
                        {/* Checkbox or Radio indicator */}
                        {!isReviewMode && (
                          <div className="flex-shrink-0 mt-0.5">
                            {isMultipleChoice ? (
                              // Checkbox for multiple choice
                              <div className={`w-5 h-5 rounded border-2 flex items-center justify-center ${
                                isSelected ? 'bg-blue-500 border-blue-500' : 'border-gray-400'
                              }`}>
                                {isSelected && <span className="text-white text-xs">✓</span>}
                              </div>
                            ) : (
                              // Radio for single choice
                              <div className={`w-5 h-5 rounded-full border-2 flex items-center justify-center ${
                                isSelected ? 'border-blue-500' : 'border-gray-400'
                              }`}>
                                {isSelected && <div className="w-3 h-3 rounded-full bg-blue-500"></div>}
                              </div>
                            )}
                          </div>
                        )}
                        
                        <div className="flex-1">
                          <span className="font-medium mr-3">
                            {String.fromCharCode(65 + index)}.
                          </span>
                          {answer.text}
                        </div>
                        
                        {isReviewMode && (() => {
                          const isUserAnswer = isMultipleChoice
                            ? Array.isArray(userAnswer) && userAnswer.includes(answer.id)
                            : userAnswer === answer.id;
                          const isCorrectAnswer = answer.isCorrect === true;
                          
                          if (isUserAnswer && isCorrectAnswer) {
                            // Мой правильный ответ - синяя галочка
                            return <span className="ml-2 text-blue-500 font-bold">✓</span>;
                          } else if (isUserAnswer && !isCorrectAnswer) {
                            // Мой неправильный ответ - красный крестик
                            return <span className="ml-2 text-red-600 font-bold">✗</span>;
                          } else if (!isUserAnswer && isCorrectAnswer) {
                            // Правильный ответ где я не отвечал - зеленая галочка
                            return <span className="ml-2 text-green-600 font-bold">✓</span>;
                          }
                          // Для неправильных ответов где я не отвечал - ничего не показываем
                          return null;
                        })()}
                      </button>
                    );
                  })}
                </div>
                
                {/* Изображение решения - показывается только в режиме просмотра результатов */}
                {isReviewMode && currentQuestion?.solutionImageUrl && (
                  <div className="mt-6 pt-6 border-t">
                    <div className="space-y-3">
                      <div className="flex items-center gap-2 text-sm font-medium text-muted-foreground">
                        <i className="fas fa-lightbulb text-yellow-500"></i>
                        <span>Решение:</span>
                      </div>
                      <div 
                        className="cursor-pointer transition-transform hover:scale-[1.02]"
                        onClick={() => {
                          setSelectedImage(currentQuestion.solutionImageUrl!);
                          setImageModalOpen(true);
                        }}
                      >
                        <img 
                          src={currentQuestion.solutionImageUrl} 
                          alt="Решение задачи" 
                          className="w-full max-w-2xl rounded-lg border shadow-md bg-muted/30"
                        />
                      </div>
                    </div>
                  </div>
                )}
                
                <div className="flex items-center justify-between pt-6">
                  <Button
                    variant="outline"
                    onClick={() => setCurrentQuestionIndex(Math.max(0, currentQuestionIndex - 1))}
                    disabled={currentQuestionIndex === 0}
                    data-testid="button-previous-question"
                  >
                    <i className="fas fa-chevron-left mr-2"></i>
                    Назад
                  </Button>

                  {/* Subject-scoped pagination: only show questions that belong to current subject */}
                  <div className="flex items-center gap-2">
                    {(() => {
                      const curSubjectName = currentQuestion?.subjectName;
                      if (!curSubjectName) return null;
                      const subject = finalTestData.testData.find(s => s.subject.name === curSubjectName);
                      if (!subject) return null;
                      return (
                        <div className="flex items-center gap-2">
                          {(() => {
                            const total = subject.questions.length;
                            const localIndex = subject.questions.findIndex(qi => qi.id === currentQuestion?.id);
                            const windowSize = 9; // unified window size for mobile & desktop
                            const half = Math.floor(windowSize / 2);
                            let start = Math.max(0, localIndex - half);
                            let end = Math.min(total, start + windowSize);
                            if (end - start < windowSize) start = Math.max(0, end - windowSize);

                            const buttons = [] as any[];
                            for (let li = start; li < end; li++) {
                              const q = subject.questions[li];
                              const globalIndex = allQuestions.findIndex(aq => aq.id === q.id);
                              const answered = !!userAnswers[q.id];
                              const active = globalIndex === currentQuestionIndex;
                              buttons.push(
                                <Button
                                  key={q.id}
                                  variant={active ? "default" : "outline"}
                                  size="sm"
                                  className={`h-8 w-8 p-0 ${answered ? 'bg-accent/20 border-accent text-accent-foreground' : ''}`}
                                  onClick={() => setCurrentQuestionIndex(globalIndex)}
                                  data-testid={`button-subject-question-${li+1}`}
                                >{li+1}</Button>
                              );
                            }
                            return buttons;
                          })()}
                        </div>
                      );
                    })()}
                  </div>

                  <div className="flex items-center gap-2">
                    {!isReviewMode && currentQuestionIndex === allQuestions.length - 1 ? (
                      <Button
                        onClick={handleSubmitTest}
                        disabled={submitTestMutation.isPending}
                        className="bg-accent hover:bg-accent/90"
                        data-testid="button-submit-test"
                      >
                        {submitTestMutation.isPending ? "Завершение..." : "Завершить тест"}
                      </Button>
                    ) : (
                      <>
                        <Button
                          onClick={() => setCurrentQuestionIndex(Math.min(allQuestions.length - 1, currentQuestionIndex + 1))}
                          data-testid="button-next-question"
                        >
                          Далее
                          <i className="fas fa-chevron-right ml-2"></i>
                        </Button>
                        {!isReviewMode && (
                          <Button
                            variant="ghost"
                            onClick={handleSubmitTest}
                            data-testid="button-inline-finish"
                            className="ml-2 text-sm"
                          >
                            Завершить тест
                          </Button>
                        )}
                      </>
                    )}
                    {isReviewMode && (
                      <Button
                        variant="outline"
                        onClick={() => setLocation("/results")}
                        data-testid="button-back-to-results"
                      >
                        <i className="fas fa-arrow-left mr-2"></i>
                        Назад к результатам
                      </Button>
                    )}
                  </div>
                </div>
              </CardContent>
            </Card>
          </div>

          {/* Right sidebar removed as per request */}
        </div>

        {/* external pagination removed (navigation shown inside question card) */}

        {/* Fixed finish button bottom-right - только в режиме тестирования */}
        {!isReviewMode && (
          <div>
            <Button onClick={handleSubmitTest} data-testid="button-finish-bottom" className="fixed bottom-6 right-6 z-50 bg-accent hover:bg-accent/90">Завершить тест</Button>
          </div>
        )}

        {/* Tools Modals */}
        <TestToolsModal
          showCalculator={showCalculator}
          showPeriodicTable={showPeriodicTable}
          onCloseCalculator={handleCloseCalculator}
          onClosePeriodicTable={handleClosePeriodicTable}
        />

        {/* Image Modal */}
        {imageModalOpen && selectedImage && (
          <div className="fixed inset-0 z-50 flex items-center justify-center">
            {/* Overlay */}
            <div 
              className="fixed inset-0 bg-black/80 animate-in fade-in-0" 
              onClick={() => {
                setImageModalOpen(false);
                setSelectedImage(null);
              }}
            />
            
            {/* Modal Content */}
            <div className="relative z-50 w-full max-w-[90vw] max-h-[90vh] bg-background border rounded-lg shadow-lg p-0 overflow-hidden animate-in zoom-in-95">
              {/* Close button */}
              <button
                onClick={() => {
                  setImageModalOpen(false);
                  setSelectedImage(null);
                }}
                className="absolute right-4 top-4 z-10 rounded-sm opacity-70 bg-background ring-offset-background transition-opacity hover:opacity-100 focus:outline-none focus:ring-2 focus:ring-ring focus:ring-offset-2 p-2"
              >
                <i className="fas fa-times h-4 w-4"></i>
                <span className="sr-only">Close</span>
              </button>
              
              <span id="image-modal-description" className="sr-only">Изображение в полном размере</span>
              <div className="relative w-full h-full flex items-center justify-center bg-background p-6">
                <img 
                  src={selectedImage} 
                  alt="Изображение в полном размере" 
                  className="max-w-full max-h-[85vh] object-contain"
                />
              </div>
            </div>
          </div>
        )}

        {/* Submit Test Confirmation Dialog */}
        <AlertDialog open={showSubmitDialog} onOpenChange={setShowSubmitDialog}>
          <AlertDialogContent>
            <AlertDialogHeader>
              <AlertDialogTitle>Завершить тест?</AlertDialogTitle>
              <AlertDialogDescription>
                {Object.keys(userAnswers).length < allQuestions.length ? (
                  <>
                    Вы ответили только на <strong>{Object.keys(userAnswers).length}</strong> из <strong>{allQuestions.length}</strong> вопросов.
                    <br /><br />
                    Неотвеченные вопросы будут засчитаны как неправильные.
                    <br /><br />
                    Вы уверены, что хотите завершить тест?
                  </>
                ) : (
                  <>
                    Вы ответили на все вопросы.
                    <br /><br />
                    Завершить тест и посмотреть результаты?
                  </>
                )}
              </AlertDialogDescription>
            </AlertDialogHeader>
            <AlertDialogFooter>
              <AlertDialogCancel>Отмена</AlertDialogCancel>
              <AlertDialogAction onClick={confirmSubmitTest} className="bg-blue-500 hover:bg-blue-700">
                Завершить тест
              </AlertDialogAction>
            </AlertDialogFooter>
          </AlertDialogContent>
        </AlertDialog>

        {/* Video proctoring removed */}


      </main>
    </div>
  );
}

