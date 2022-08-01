
library(shiny)
library(shinythemes)
library(dplyr)
library(shinyWidgets)
library(highcharter)
library(plotly)
library(shinydashboard)
library(shinyjs)
library(lubridate)
library(sqldf)
library(tidyverse)


# Construction de l'application R shiny : front end interface
ui <- fluidPage(
  useShinydashboard(),
  
  #Barre de navigation dans l'application
  navbarPage("Analyse des règles d'intrusion",theme = shinytheme("sandstone"),
    tags$head(
      # Include our custom CSS
        includeCSS("style.css")
    ),
             
    tabPanel('Visualisation des données', icon = icon("table"),
             fluidRow(
               valueBoxOutput("vbox", width=3),
               valueBoxOutput("vbox2", width=3),
               valueBoxOutput("vbox3", width=3),
               valueBoxOutput("vbox4", width=3),
             ),
             br(),
             DT::DTOutput('table_log')       
             
    ),
    tabPanel('Statistiques descriptives des données', icon = icon("chart-bar"),
        tabsetPanel(  
          
          # 1er onglet : 
           tabPanel('Flux rejetés et autorisés',
             br(),
             sidebarLayout(
               sidebarPanel("Filtrage des données",
                 absolutePanel(id = "controls", class = "panel panel-default", fixed = TRUE,
                               draggable = TRUE, top = 250, left = 20, right = "auto", bottom = "auto",
                               width = 330, height = "auto",
                               
                               titlePanel(h4("Plage de ports :",style='color:blue;padding-left: 15px')),
                               selectInput("rfc_6065", "",
                                           choices = c("The Well-Known Ports" = "well_known",
                                                       "The Registered Ports" = "registered",
                                                       "The Dynamic and/or Private Ports" = "dynamic_private")),
                               
                               titlePanel(h4("Type d'action :",style='color:blue;padding-left: 15px')),
                               checkboxGroupInput("flux", "",
                                            choices = c("Flux rejetés" = "Deny", "Flux autorisés" = "Permit"), selected ="Deny")
                               
               ),width = 2  
               
             ),
             
              mainPanel(
                DT::DTOutput('log_filtered'),
                br(),
                highchartOutput('piechart'),
                br(),
                highchartOutput('histchart'),
                width=10
              )
            )
        ),
        
        # 2ème onglet : 
        tabPanel('Visualisation interactive des IP source',
                 br(),
                 sidebarLayout(
                   sidebarPanel("Filtrage des données",
                                absolutePanel(id = "controls", class = "panel panel-default", fixed = TRUE,
                                              draggable = TRUE, top = 250, left = 20, right = "auto", bottom = "auto",
                                              width = 330, height = "auto",
                                              
                                              titlePanel(h4("Parcourir les IP :",style='color:blue;padding-left: 15px')),                            
                                              sliderInput("sliderip", "", min=1, max=40, value=5),
                                              titlePanel(h4("Adresse IP source :",style='color:blue;padding-left: 15px')),
                                              verbatimTextOutput("ip"),
                                              titlePanel(h4("Nombre de Deny :",style='color:blue;padding-left: 15px')),
                                              verbatimTextOutput("nb_deny"),
                                              titlePanel(h4("Nombre de Permit :",style='color:blue;padding-left: 15px')),
                                              verbatimTextOutput("nb_permit"),
                                              titlePanel(h4("Nombre d'IP de destination contactées :",style='color:blue;padding-left: 15px')),
                                              verbatimTextOutput("nb_ip")
                                              
                                ),width = 2  
                                
                   ),
                   
                   mainPanel(
                     highchartOutput('parcourir'),
                     width=10
                   )
                 )
                 
        ),
        
        # 3ème onglet : 
        tabPanel('Classement des IP et des ports',
                 br(),
                 sidebarLayout(
                   sidebarPanel("Filtrage des données",
                                absolutePanel(id = "controls", class = "panel panel-default", fixed = TRUE,
                                              draggable = TRUE, top = 250, left = 20, right = "auto", bottom = "auto",
                                              width = 330, height = "auto",
                                
                                titlePanel(h4("Nombre d'IP sources les plus émettrices :",style='color:blue;padding-left: 15px')),                            
                                sliderInput("slidertop5", "", min=5, max=15, value=5), 
                                
                                titlePanel(h4("Nombre de Well-Known ports avec un accès autorisé :",style='color:blue;padding-left: 15px')),                            
                                sliderInput("slidertop10", "", min=5, max=15, value=10)
                                              
                                ),width = 2  
                                
                   ),
                   
                   mainPanel(
                     highchartOutput('top5'),
                     highchartOutput('top10'),
                     width=10
                   )
                 )
        ),
        
        
        
      )
    ),
    tabPanel('Analyse des données'),
    
    
  )
)


# backend logic
server <- function(input, output, session){
  
  # Fonction permettant de charger les données
  log_function = reactive({
    log = read.table("firewall.csv", header=TRUE, sep=";")
  })
  
  # Fonction qui retourne sous forme de table le jeu de données
  output$table_log <- DT::renderDT({
    data = log_function()
    
  })
  
  # Fonction permettant de filtrer selon le port
  output$log_filtered <- DT::renderDataTable({
    data = log_function()
    data %>% 
      filter(rfc_6065 %in% input$rfc_6065) %>%
      filter(action %in% input$flux) 
  })
  
  # Chiffre clés : Date à laquelle les données ont été récupérées
  output$vbox <- renderValueBox({
    data = log_function()
    valueBox(data$datetime[1],
             subtitle = "Date de la récupération des logs",
             color = "blue")
  })
  
  # Chiffre clés : Nombre de logs 
  output$vbox2 <- renderValueBox({
    data = log_function()
    valueBox(dim(data)[1],
      subtitle = "Nombre de logs récupérés",
      color = "purple")
  })
  
  # Chiffre clés : Nombre de flux rejetés
  output$vbox3 <- renderValueBox({
    data = log_function()
    valueBox(sum(data$action=="Deny"),
             subtitle = "Nombre de flux rejetés",
             color = "red")
  })
  
  # Chiffre clés : Nombre de flux autorisés
  output$vbox4 <- renderValueBox({
    data = log_function()
    valueBox(sum(data$action=="Permit"),
             subtitle = "Nombre de flux autorisés",
             color = "green")
  })
    
  # Visualisation de la répartition des protocoles TCP/UDP
  output$piechart <- renderHighchart({
    data = log_function()
    data = data %>%
      filter(action %in% input$flux) %>%
      filter(rfc_6065 %in% input$rfc_6065)
      highchart() %>%
        hc_chart(type = "pie") %>%
        hc_add_series(data$proto) %>%
        hc_title(text="Répartition des protocoles TCP et UDP")
  })
  
  # Visualisation des ports destination TCP 
  output$histchart <- renderHighchart({
    data = log_function()
    data = data %>%
        filter(action %in% input$flux) %>%
        filter(rfc_6065 %in% input$rfc_6065)
    df = as.data.frame(head(n=10,sort(table(subset(data, select=c(dstport), c(data$proto=="TCP"))),decreasing = TRUE)))
    colnames(df) = c("var","freq")
    
    df %>% hchart("lollipop", hcaes(x=var, y=freq)) %>%
      hc_title(text="Fréquence des ports de destination TCP") 
  })
  
  # Visualisation interactive des IP source
  output$parcourir <- renderHighchart({
    data = log_function()
    #sql <- "select indice, action, count(indice) as Nb_ip from data group by action, indice"
    sql <- "select ipsrc, ipdst, indice, action, count(ipdst) as Nb_ip from data where action='Permit' group by indice "
    sql <- sqldf(sql)
    sql <- as.data.frame(sql)
    sql2 <- "select ipsrc, ipdst, indice, action, count(ipdst) as Nb_ip from data where action='Deny' group by indice "
    sql2 <- sqldf(sql2)
    sql2 <- as.data.frame(sql2)
    sql %>% hchart(
        'scatter', hcaes(x=indice, y=Nb_ip, group=action)) %>%
      hc_add_series(
        sql2, 'scatter', hcaes(x=indice, y=Nb_ip, group=action)
      ) %>%
      hc_tooltip(followPointer=TRUE, enableMouseTracking = TRUE) %>%
      hc_yAxis(title=list(text="Nombre IP destination contactées")) %>%
      hc_xAxis(title=list(text="Indice Ip source")) 
    
  })
  
  # Visualisation des IP en temps réels
  output$ip <- renderPrint({
     data = log_function()
     data %>%
       filter(indice==input$sliderip) %>% distinct(ipsrc) %>%
        pull(ipsrc)
  })
  
  # Nombre de deny
  output$nb_deny <- renderPrint({
    data = log_function()
    data %>%
      filter(indice==input$sliderip) %>% 
      filter(action=="Deny") %>%
      count() %>% pull()
  })
  
  # Nombre de permit
  output$nb_permit <- renderPrint({
    data = log_function()
    data %>%
      filter(indice==input$sliderip) %>% 
      filter(action=="Permit") %>%
      count() %>% pull()
  })
  
  # Nombre d'IP de destination contactées
  output$nb_ip <- renderPrint({
    data = log_function()
    data %>%
      filter(indice==input$sliderip) %>% count(ipdst) %>%
      pull()
  })
  
  # TOP 5 des IP sources les plus émettrices
  output$top5 <- renderHighchart({
    data = log_function()
    df = as.data.frame(head(n=input$slidertop5,sort(table(subset(data, select=c(ipsrc))),decreasing = TRUE)))
    colnames(df) = c("var","freq")
    
    df %>% hchart("bar", hcaes(x=var, y=freq)) %>%
      hc_title(text="Top des IP sources les plus émettrices") 
  })
  
  # TOP 10 des ports inférieurs à 1024 avec un accès autorisé
  output$top10 <- renderHighchart({
    data = log_function()
    df = as.data.frame(head(n=input$slidertop10,sort(table(subset(data, data$action=="Permit" & data$rfc_6065 =="well_known", select=c(dstport))),decreasing = TRUE)))
    colnames(df) = c("var","freq")
    
    df %>% hchart("bar", hcaes(x=var, y=freq)) %>%
      hc_title(text="Top des ports inférieurs à 1024 avec un accès autorisé") 
  })
  
  
}


# Démarrage de l'application
shinyApp(ui=ui, server=server)

