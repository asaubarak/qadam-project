import { useQuery } from "@tanstack/react-query";
import { useAuth } from "@/hooks/use-auth";
import Header from "@/components/layout/header";
import Footer from "@/components/layout/footer";
import { Card, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { useLocation } from "wouter";
import type { Block, TestResult, UserRanking } from "@shared/schema";

interface ProfileData {
  user: any;
  testResults: TestResult[];
  ranking: UserRanking;
  subjectProgress: any[];
}

export default function HomePage() {
  const { user } = useAuth();
  const [, setLocation] = useLocation();

  const { data: blocks, isLoading: blocksLoading } = useQuery<(Block & { variantCount: number; totalQuestions: number })[]>({
    queryKey: ["/api/public/blocks"],
  });

  const { data: profileData } = useQuery<ProfileData>({
    queryKey: ["/api/profile"],
    enabled: !!user,
  });



  if (blocksLoading) {
    return (
      <div className="min-h-screen bg-blue-100">
        <Header />
        <main className="container mx-auto px-4 lg:px-6 py-8">
          <div className="space-y-6">
            <Skeleton className="h-20 w-full" />
            <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
              {[...Array(4)].map((_, i) => (
                <Skeleton key={i} className="h-32" />
              ))}
            </div>
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
              {[...Array(6)].map((_, i) => (
                <Skeleton key={i} className="h-64" />
              ))}
            </div>
          </div>
        </main>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-blue-100">
      <Header />
      <main className="container mx-auto px-3 md:px-4 lg:px-6 py-4 md:py-8">
        {/* Welcome Section */}
        <div className="mb-4 md:mb-8 text-left">
          <h1 className="text-lg md:text-3xl font-bold text-foreground mb-1 md:mb-2">
            Қош келдіңіз, <span className="text-primary">{user?.username}</span>!
          </h1>
          <p className="text-xs md:text-base text-muted-foreground">
            ҰБТ-ға дайындалу үшін тест блогын таңдаңыз
          </p>
        </div>



        {/* Test Blocks Grid */}
        <div className="mb-6 md:mb-8">
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3 md:gap-6">
            {blocks?.map((block) => (
          <Card 
            key={block.id} 
            className="group hover:shadow-md transition-all duration-200 cursor-pointer flex flex-col rounded-sm h-[200px] md:h-[300px]"
            onClick={() => setLocation(`/block/${block.id}`)}
            data-testid={`card-block-${block.id}`}
          >
            <CardContent className="p-3 md:p-6 flex flex-col h-full flex-grow text-left">
              {/* Название блока и прогресс */}
              <div className="flex items-start justify-between gap-2 md:gap-3">
                <div className="flex-1 min-w-0">
                  <h3 className="text-base md:text-2xl lg:text-3xl font-semibold text-foreground mb-1 group-hover:text-primary transition-colors">
                    {block.name}
                  </h3>
                  <p className="text-xs md:text-lg lg:text-xl text-muted-foreground line-clamp-2 mt-1 md:mt-2">
                    {block.name.includes('Физика') && "Физика мен математика бойынша кешенді дайындық"}
                    {block.name.includes('Химия') && "Химия мен биология бойынша қарқынды дайындық"}
                    {block.name.includes('История') && "Қазақстан тарихы мен география бойынша дайындық"}
                    {!block.name.includes('Физика') && !block.name.includes('Химия') && !block.name.includes('История') && "ҰБТ-ға дайындық тест блогы"}
                  </p>
                </div>
                
                {/* Progress circle */}
                <div className="relative w-10 h-10 md:w-16 md:h-16 flex-shrink-0">
                  <svg className="w-full h-full -rotate-90" viewBox="0 0 100 100">
                    <circle
                      cx="50"
                      cy="50"
                      r="42"
                      fill="none"
                      stroke="currentColor"
                      strokeWidth="6"
                      strokeLinecap="round"
                      className="text-muted/20"
                    />
                    <circle
                      cx="50"
                      cy="50"
                      r="42"
                      fill="none"
                      stroke="currentColor"
                      strokeWidth="6"
                      strokeLinecap="round"
                      strokeDasharray="263.89"
                      strokeDashoffset="65.97"
                      className="text-primary"
                    />
                  </svg>
                  <div className="absolute inset-0 flex items-center justify-center">
                    <span className="text-xs md:text-lg font-bold text-primary">75+</span>
                  </div>
                </div>
              </div>
              
              {/* Пустое пространство, которое займет всю доступную высоту */}
              <div className="flex-grow"></div>
              
              {/* Кнопка - всегда внизу */}
              <Button 
                className="w-full h-8 md:h-12 rounded-[2px] bg-blue-500 hover:bg-blue-700 text-white font-semibold mt-auto text-xs md:text-base"
                onClick={(e) => {
                  e.stopPropagation();
                  setLocation(`/block/${block.id}`);
                }}
                data-testid={`button-start-${block.id}`}
              >
                ТЕГІН НҰСҚА
              </Button>
            </CardContent>
          </Card>
            )) || []}
          </div>
        </div>


      </main>
      <Footer />
    </div>
  );
}