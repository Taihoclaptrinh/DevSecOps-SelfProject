pipeline {
    agent {
        label 'devsecops'
    }
    environment {
        TAG_NAME = "${env.BUILD_NUMBER}-${env.GIT_COMMIT?.take(4)}"
        GIT_COMMIT_SHORT = "${env.GIT_COMMIT ?: 'unknown'}".take(7)

        DOCKER_REPO = "chitaialm/devsecops"
        SONAR_REPORT = "sonar_analysis_${env.JOB_NAME}_${GIT_COMMIT_SHORT}_report"
        SONAR_PROJECT_KEY = 'DevSecOps'
        TRIVYFS_REPORT = "trivy_scan_${env.JOB_NAME}_${GIT_COMMIT_SHORT}_report.html"

        
    }
    stages {
        stage('Checkout') {
            steps {
                checkout scm
            }
        }
        stage('Authenticate Snyk') {
            steps {
                withCredentials([string(credentialsId: 'snyk-token', variable: 'SNYK_TOKEN')]) {
                    sh 'snyk auth $SNYK_TOKEN'  
                }
            }
        }
        stage('Install Dependencies') {
            steps {
                sh 'npm install'

                dir('Frontend') {
                    sh 'npm install'
                }
            }
        }

        stage('Snyk Security Check') {
            steps {
                script {
                    sh 'snyk test --json > backend-snyk.json || true'
                    sh 'snyk-to-html -i backend-snyk.json -o backend-snyk.html'
                    
                    dir('Frontend') {
                        sh 'snyk test --json > frontend-snyk.json || true'
                        sh 'snyk-to-html -i frontend-snyk.json -o frontend-snyk.html'
                    }
                    // Lưu trữ báo cáo HTML
                    archiveArtifacts artifacts: 'backend-snyk.html, Frontend/frontend-snyk.html', 
                                    allowEmptyArchive: true
                }
            }
        }
        stage('Code Scan(SonarQube Analysis)') {
            steps {
                script {
                    withCredentials([
                        string(credentialsId: 'sonar-host-url', variable: 'SONAR_HOST_URL'),
                        string(credentialsId: 'sonar-token', variable: 'SONAR_TOKEN')
                    ]) {
                       sh '''
                            /opt/sonar-scanner/bin/sonar-scanner \
                            -Dsonar.projectKey=$SONAR_PROJECT_KEY \
                            -Dsonar.sources=. \
                            -Dsonar.host.url=$SONAR_HOST_URL \
                            -Dsonar.login=$SONAR_TOKEN
                        '''
                        archiveArtifacts artifacts: 'dependency-check-report/*.html, dependency-check-log.txt', allowEmptyArchive: true
                    }
                }
            }
        }

        stage('Build Backend') {
            steps {
                script {
                    sh """
                        docker build -t backend:${TAG_NAME} .
                        echo " Image tag: ${TAG_NAME}"
                    """
                }
            }
        }
        stage('Build Frontend') {
            steps {
                script {
                    sh """
                        cd Frontend && docker build -t frontend:${TAG_NAME} .
                        echo " Image tag: ${TAG_NAME}"
                    """
                }
            }
        }
        stage('Security Scan with Trivy') {
            steps {
                script {
                    sh """
                    set -e
                    echo "🔍 Running Trivy filesystem scan (skipping large logs)..."
                    docker run --rm -v \$PWD:/workspace -v /var/run/docker.sock:/var/run/docker.sock \
                    aquasec/trivy fs /workspace --severity HIGH,CRITICAL --scanners vuln \
                    --skip-files /workspace/dependency-check-log.txt \
                    --format template --template "@contrib/html.tpl" \
                    --output /workspace/trivy/\$TRIVYFS_REPORT || echo "⚠️ Trivy FS scan failed"

                    echo "🔍 Running Trivy image scan for Backend..."
                    docker run --rm -v \$PWD:/workspace -v /var/run/docker.sock:/var/run/docker.sock \
                    aquasec/trivy image backend:${TAG_NAME} --severity HIGH,CRITICAL --scanners vuln \
                    --format template --template "@contrib/html.tpl" \
                    --output /workspace/trivy/trivy_backend_scan.html || echo "⚠️ Trivy Backend scan failed"

                    echo "🔍 Running Trivy image scan for Frontend..."
                    docker run --rm -v \$PWD:/workspace -v /var/run/docker.sock:/var/run/docker.sock \
                    aquasec/trivy image frontend:${TAG_NAME} --severity HIGH,CRITICAL --scanners vuln \
                    --format template --template "@contrib/html.tpl" \
                    --output /workspace/trivy/trivy_frontend_scan.html || echo "⚠️ Trivy Frontend scan failed"
                    """
                    
                    archiveArtifacts artifacts: "${TRIVYFS_REPORT}, trivy_backend_scan.html, trivy_frontend_scan.html", allowEmptyArchive: true
                }
            }
        }

        stage('Login to Docker Hub'){
            steps {
                withCredentials([usernamePassword(credentialsId: 'dockerhub', usernameVariable: 'DOCKER_USER', passwordVariable: 'DOCKER_PASS')]) {
                    sh """
                        echo \$DOCKER_PASS | docker login -u \$DOCKER_USER --password-stdin
                    """
                }
            }
        }
        stage('Push to Docker Hub') {
            steps {
                script {
                    sh """
                        docker tag backend:${TAG_NAME} ${DOCKER_REPO}:backend-${TAG_NAME}
                        docker tag frontend:${TAG_NAME} ${DOCKER_REPO}:frontend-${TAG_NAME}
                    """
                    sh """
                        docker push ${DOCKER_REPO}:backend-${TAG_NAME} && docker rmi backend:${TAG_NAME} ${DOCKER_REPO}:backend-${TAG_NAME} || echo "Push failed, keeping image"
                        docker push ${DOCKER_REPO}:frontend-${TAG_NAME} && docker rmi frontend:${TAG_NAME} ${DOCKER_REPO}:frontend-${TAG_NAME} || echo "Push failed, keeping image"
                    """
                }
            }
        }


        stage('Deploy') {
            steps {
                script {
                    sh """
                        docker pull ${DOCKER_REPO}:backend-${TAG_NAME} || exit 1
                        docker pull ${DOCKER_REPO}:frontend-${TAG_NAME} || exit 1
                    """

                    sh """
                        docker inspect backend &> /dev/null && docker stop backend || true
                        docker inspect frontend &> /dev/null && docker stop frontend || true
                    """

                    sh """
                        docker tag ${DOCKER_REPO}:backend-${TAG_NAME} backend:v1
                        docker tag ${DOCKER_REPO}:frontend-${TAG_NAME} frontend:v1
                    """
                    
                    sh """
                        docker rmi ${DOCKER_REPO}:backend-${TAG_NAME} || true
                        docker rmi ${DOCKER_REPO}:frontend-${TAG_NAME} || true
                    """

                    sh """
                        docker-compose up -d 
                    """
                }
            }
        }
    }
    post {
        always {
            archiveArtifacts artifacts: "${TRIVYFS_REPORT}", allowEmptyArchive: true
        }
    }
}
